"""Certificate class inheriting from ConfigStanza for unified collection support"""
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
import binascii
from typing import List, Optional, TYPE_CHECKING
from f5_config_parser.stanza import ConfigStanza

if TYPE_CHECKING:
    from f5_config_parser.collection import StanzaCollection


class Certificate(ConfigStanza):
    """Represents an F5 certificate as a ConfigStanza for unified collection support"""

    def __init__(self, cert_filename: str, cert: x509.Certificate,
                 cert_pem_data: Optional[str] = None,
                 key_filename: Optional[str] = None,
                 key_pem_data: Optional[str] = None):
        """
        Create Certificate from parsed x509 certificate and initialise as ConfigStanza

        Args:
            cert_filename: Clean certificate filename e.g., '/Common/mycert.crt'
            cert: Parsed x509.Certificate object
            cert_pem_data: Optional PEM data for the certificate
            key_filename: Optional clean filename for the matching key
            key_pem_data: Optional PEM data for the matching key
        """
        # Map certificate to ConfigStanza interface
        prefix = ('certificate', 'object')
        name = cert_filename
        config_lines = []

        # Initialise parent ConfigStanza first
        super().__init__(prefix=prefix, name=name, config_lines=config_lines)

        # Store basic info
        self.filename = cert_filename
        self.pem_data = cert_pem_data
        self.key_filename = key_filename
        self.key_pem_data = key_pem_data

        # Extract certificate metadata
        self.subject = cert.subject.rfc4514_string()
        self.issuer = cert.issuer.rfc4514_string()
        self.serial_number = str(cert.serial_number)
        self.not_valid_before = cert.not_valid_before_utc
        self.not_valid_after = cert.not_valid_after_utc
        self.signature_algorithm = cert.signature_algorithm_oid._name

        # Extract SKI (Subject Key Identifier)
        self.ski = None
        try:
            ski_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            self.ski = binascii.hexlify(ski_ext.value.digest).decode('ascii').upper()
        except x509.ExtensionNotFound:
            pass

        # Extract AKI (Authority Key Identifier)
        self.aki = None
        try:
            aki_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            if aki_ext.value.key_identifier:
                self.aki = binascii.hexlify(aki_ext.value.key_identifier).decode('ascii').upper()
        except x509.ExtensionNotFound:
            pass

        # Extract AIA and OCSP
        self.aia = None
        self.ocsp_uri = None
        try:
            aia_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            self.aia = aia_ext.value

            # Extract OCSP URI from AIA
            for access_description in self.aia:
                if access_description.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    self.ocsp_uri = access_description.access_location.value
                    break
        except x509.ExtensionNotFound:
            pass

        # Check if it's a CA certificate
        self.is_ca = False
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
            self.is_ca = basic_constraints.value.ca
        except x509.ExtensionNotFound:
            pass

    @property
    def cert_id(self) -> str:
        """
        Unique certificate identifier based on serial number and issuer.

        This provides a consistent way to uniquely identify certificates
        for use in sets, dictionary keys, and equality comparisons.

        Returns:
            str: Concatenated serial number and issuer
        """
        return f"{self.serial_number}|{self.issuer}"

    def _discover_dependencies(self, collection: 'StanzaCollection') -> List[str]:
        """
        Discover certificate dependencies (e.g., key files, CA certificates)
        """
        dependency_paths = []

        # Look for matching key file
        if self.key_filename:
            key_path = collection.resolve_object_by_name(
                self.key_filename, ('certificate', 'object')
            )
            if key_path:
                dependency_paths.append(key_path)

        # Look for CA certificate if this is not a CA and has AKI
        if not self.is_ca and self.aki:
            # Find CA certificate with matching SKI
            ca_certs = collection.filter(prefix=('certificate', 'object'))
            for ca_cert_stanza in ca_certs:
                if (hasattr(ca_cert_stanza, 'is_ca') and ca_cert_stanza.is_ca and
                        hasattr(ca_cert_stanza, 'ski') and ca_cert_stanza.ski == self.aki):
                    dependency_paths.append(ca_cert_stanza.full_path)
                    break

        return dependency_paths

    def __repr__(self):
        cn = [x.replace('CN=', '') for x in self.subject.split(',') if 'CN=' in x]
        cn_str = cn[0] if cn else 'Unknown'
        pem_status = " (PEM loaded)" if self.pem_data else ""
        return f"<Certificate {'CA' if self.is_ca else 'Cert'}: {cn_str} - File: {self.filename} - Exp: {self.not_valid_after}{pem_status}>"

    def __str__(self):
        """
        Override string representation for certificate objects
        """
        lines = [f"{self.full_path} {{"]
        lines.append(f"    # Certificate: {self.filename}")
        lines.append(f"    # Subject: {self.subject}")
        lines.append(f"    # Expiry: {self.not_valid_after.strftime('%Y-%m-%d')}")
        lines.append(f"    # Issuer: {self.issuer}")

        if self.is_ca and self.ski:
            lines.append(f"    # SKI: {self.ski}")

        if self.aki:
            lines.append(f"    # AKI: {self.aki}")

        lines.append("}\n")

        return "\n".join(lines)

    def __hash__(self) -> int:
        """Hash based on full path and cert id for uniqueness in collections"""
        return hash((self.full_path, self.cert_id))

    def __eq__(self, other) -> bool:
        """
        Compare certificates based on type:
        - When compared to string: compare full_path only (for set operations and filtering)
        - When compared to Certificate: compare full_path AND cert_id (for detailed analysis)
        """
        if isinstance(other, str):
            # String comparison - just check full_path (enables set operations with name strings)
            return self.full_path == other
        elif isinstance(other, Certificate):
            # Object comparison - check both full_path and cert_id
            return self.full_path == other.full_path and self.cert_id == other.cert_id
        else:
            return False

    def _do_parse(self) -> dict:
        """
        Build parsed config dictionary from certificate attributes.
        Certificate parsing happens in __init__, this just packages it.
        """
        return {
            'filename': self.filename,
            'subject': self.subject,
            'issuer': self.issuer,
            'serial_number': self.serial_number,
            'not_valid_before': self.not_valid_before,
            'not_valid_after': self.not_valid_after,
            'signature_algorithm': self.signature_algorithm,
            'ski': self.ski,
            'aki': self.aki,
            'ocsp_uri': self.ocsp_uri,
            'is_ca': self.is_ca,
            'key_filename': self.key_filename,
        }

    def verify_key_match(self) -> bool:
        """
        Verify that the certificate and private key match

        Returns:
            True if certificate and key match, False otherwise

        Raises:
            ValueError: If verification cannot be performed or fails
        """
        if self.is_ca:
            return False  # Just return False for CA certs, don't raise

        if not self.pem_data:
            raise ValueError("Certificate PEM data not loaded")

        if not self.key_pem_data:
            raise ValueError("Key PEM data not available")

        # Load certificate
        cert = x509.load_pem_x509_certificate(self.pem_data.encode('utf-8'), default_backend())
        cert_public_key = cert.public_key()

        # Load private key
        private_key = serialization.load_pem_private_key(
            self.key_pem_data.encode('utf-8'),
            password=None,
            backend=default_backend()
        )

        # Compare public keys by checking if they're mathematically equivalent
        cert_public_numbers = cert_public_key.public_numbers()
        private_public_numbers = private_key.public_key().public_numbers()

        return cert_public_numbers == private_public_numbers