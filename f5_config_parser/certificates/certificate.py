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

    def __init__(self, clean_filename: str, filesystem_filename: str, extract_dir: Path,
                 clean_to_filesystem: dict, load_pem_data: bool = False):
        """Create Certificate from file path and initialize as ConfigStanza"""

        # Map certificate to ConfigStanza interface
        prefix = ('certificate', 'object')  # Our chosen prefix for certificate objects
        name = clean_filename  # Use clean filename as the stanza name
        config_lines = []  # Certificates don't have traditional config lines

        # Initialize parent ConfigStanza first
        super().__init__(prefix=prefix, name=name, config_lines=config_lines)

        # Now load certificate data
        cert_path = extract_dir / filesystem_filename

        try:
            cert_data = cert_path.read_bytes()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        except ValueError as e:
            if clean_filename.endswith('.key'):
                raise ValueError(f"Skipping key file")
            else:
                raise ValueError(f"Failed to parse certificate {clean_filename}: {e}")
        except FileNotFoundError as e:
            raise ValueError(f"Failed to find file {clean_filename}: {e}")

        # Store basic info
        self.filename = clean_filename
        self.filesystem_filename = filesystem_filename

        # Store PEM data if requested
        self.pem_data: Optional[str] = None
        self.key_pem_data: Optional[str] = None

        if load_pem_data:
            self.pem_data = cert_data.decode('utf-8')

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

        # Check if it's a CA certificate
        self.is_ca = False
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
            self.is_ca = basic_constraints.value.ca
        except x509.ExtensionNotFound:
            pass

        # Determine matching key filename and load key PEM data if requested
        self.key_filename = None
        self.key_filesystem_filename = None
        if clean_filename.endswith('.crt'):
            potential_key_filename = clean_filename.replace('.crt', '.key')
            if potential_key_filename in clean_to_filesystem:
                self.key_filename = potential_key_filename
                self.key_filesystem_filename = clean_to_filesystem[potential_key_filename]

                # Load key PEM data if requested
                if load_pem_data:
                    key_path = extract_dir / self.key_filesystem_filename
                    try:
                        self.key_pem_data = key_path.read_text(encoding='utf-8')
                    except ValueError as e:
                        print(f"Warning: Failed to load key PEM data for {potential_key_filename}: {e}")

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

    def _do_parse(self) -> dict:
        """
        Certificate parsing is done in __init__, no additional parsing needed
        """
        raise NotImplementedError("Certificate parsing is handled in __init__")

    def __repr__(self):
        cn = [x.replace('CN=', '') for x in self.subject.split(',') if 'CN=' in x]
        cn_str = cn[0] if cn else 'Unknown'
        pem_status = " (PEM loaded)" if self.pem_data else ""
        return f"<Certificate {'CA' if self.is_ca else 'Cert'}: {cn_str} - File: {self.filename} - Exp: {self.not_valid_after}{pem_status}>"

    def __str__(self):
        """
        Override string representation for certificate objects
        """
        # Certificates don't have traditional F5 config format
        return f"{self.full_path} {{\n    # Certificate: {self.filename}\n    # Subject: {self.subject}\n}}\n"

    def __hash__(self) -> int:
        """Hash based on full path for uniqueness in collections"""
        return hash(self.full_path)

    def __eq__(self, other) -> bool:
        """Certificates are equal if they represent the same actual certificate"""
        if not isinstance(other, Certificate):
            return False
        return self.cert_id == other.cert_id

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