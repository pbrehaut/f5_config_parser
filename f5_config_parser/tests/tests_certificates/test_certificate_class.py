import pytest
import tempfile
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, timezone
import shutil
from unittest.mock import Mock, patch
import binascii

from f5_config_parser.certificates.certificate import Certificate


class TestCertificateFixtures:
    """Helper class to generate test certificates"""

    @staticmethod
    def create_private_key():
        """Generate a test RSA private key"""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

    @staticmethod
    def create_basic_cert(subject_cn="test.example.com", issuer_cn=None, is_ca=False,
                          valid_days=365, ski=None, aki=None, serial_number=None):
        """Create a basic test certificate"""
        private_key = TestCertificateFixtures.create_private_key()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AU"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "NSW"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Sydney"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organisation"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
        ])

        # Use provided issuer or same as subject for self-signed
        if issuer_cn:
            issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "AU"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "NSW"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA"),
                x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
            ])
        else:
            issuer = subject

        # Handle expired certificates properly
        if valid_days < 0:
            # For expired certificates, set both dates in the past
            not_valid_before = datetime.now(timezone.utc) + timedelta(days=valid_days - 1)  # Start before expiry
            not_valid_after = datetime.now(timezone.utc) + timedelta(days=valid_days)  # Expired date
        else:
            # Normal case
            not_valid_before = datetime.now(timezone.utc)
            not_valid_after = datetime.now(timezone.utc) + timedelta(days=valid_days)

        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            serial_number or x509.random_serial_number()
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )

        # Add basic constraints
        builder = builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None if not is_ca else 0),
            critical=True,
        )

        # Add SKI if provided or generate one
        if ski or is_ca:
            ski_bytes = binascii.unhexlify(ski) if ski else x509.SubjectKeyIdentifier.from_public_key(
                private_key.public_key()).digest
            builder = builder.add_extension(
                x509.SubjectKeyIdentifier(ski_bytes),
                critical=False,
            )

        # Add AKI if provided
        if aki:
            aki_bytes = binascii.unhexlify(aki)
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier(
                    key_identifier=aki_bytes,
                    authority_cert_issuer=None,
                    authority_cert_serial_number=None
                ),
                critical=False,
            )

        cert = builder.sign(private_key, hashes.SHA256())
        return cert, private_key


class TestCertificate:
    """Unit tests for Certificate class using mock data"""

    @pytest.fixture
    def temp_cert_dir(self):
        """Create temporary directory for test certificates"""
        temp_dir = Path(tempfile.mkdtemp())
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def basic_cert_data(self):
        """Generate basic certificate data for testing"""
        cert, key = TestCertificateFixtures.create_basic_cert()
        return {
            'cert': cert,
            'key': key,
            'cert_pem': cert.public_bytes(serialization.Encoding.PEM),
            'key_pem': key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        }

    @pytest.fixture
    def ca_cert_data(self):
        """Generate CA certificate data for testing"""
        cert, key = TestCertificateFixtures.create_basic_cert(
            subject_cn="Test CA",
            is_ca=True,
            ski="1234567890ABCDEF1234567890ABCDEF12345678"
        )
        return {
            'cert': cert,
            'key': key,
            'cert_pem': cert.public_bytes(serialization.Encoding.PEM),
            'ski': "1234567890ABCDEF1234567890ABCDEF12345678"
        }

    @pytest.fixture
    def signed_cert_data(self, ca_cert_data):
        """Generate certificate signed by CA"""
        ca_ski = ca_cert_data['ski']
        cert, key = TestCertificateFixtures.create_basic_cert(
            subject_cn="signed.example.com",
            issuer_cn="Test CA",
            aki=ca_ski
        )
        return {
            'cert': cert,
            'key': key,
            'cert_pem': cert.public_bytes(serialization.Encoding.PEM),
            'aki': ca_ski
        }

    def test_certificate_basic_initialisation(self, temp_cert_dir, basic_cert_data):
        """Test basic certificate initialisation"""
        # Write certificate to file
        cert_file = temp_cert_dir / "test.crt"
        cert_file.write_bytes(basic_cert_data['cert_pem'])

        clean_to_filesystem = {"test.crt": "test.crt"}

        cert = Certificate("test.crt", "test.crt", temp_cert_dir, clean_to_filesystem)

        assert cert.filename == "test.crt"
        assert cert.filesystem_filename == "test.crt"
        assert "CN=test.example.com" in cert.subject
        assert cert.is_ca is False
        assert cert.signature_algorithm == "sha256WithRSAEncryption"
        assert cert.serial_number is not None
        assert cert.not_valid_before is not None
        assert cert.not_valid_after is not None

    def test_certificate_with_matching_key_file(self, temp_cert_dir, basic_cert_data):
        """Test certificate that has a matching key file"""
        # Write certificate and key files
        cert_file = temp_cert_dir / "server.crt"
        key_file = temp_cert_dir / "server.key"
        cert_file.write_bytes(basic_cert_data['cert_pem'])
        key_file.write_bytes(basic_cert_data['key_pem'])

        clean_to_filesystem = {
            "server.crt": "server.crt",
            "server.key": "server.key"
        }

        cert = Certificate("server.crt", "server.crt", temp_cert_dir, clean_to_filesystem)

        assert cert.key_filename == "server.key"
        assert cert.key_filesystem_filename == "server.key"

    def test_certificate_without_matching_key_file(self, temp_cert_dir, basic_cert_data):
        """Test certificate that doesn't have a matching key file"""
        cert_file = temp_cert_dir / "standalone.crt"
        cert_file.write_bytes(basic_cert_data['cert_pem'])

        clean_to_filesystem = {"standalone.crt": "standalone.crt"}

        cert = Certificate("standalone.crt", "standalone.crt", temp_cert_dir, clean_to_filesystem)

        assert cert.key_filename is None
        assert cert.key_filesystem_filename is None

    def test_ca_certificate(self, temp_cert_dir, ca_cert_data):
        """Test CA certificate with proper attributes"""
        cert_file = temp_cert_dir / "ca.crt"
        cert_file.write_bytes(ca_cert_data['cert_pem'])

        clean_to_filesystem = {"ca.crt": "ca.crt"}

        cert = Certificate("ca.crt", "ca.crt", temp_cert_dir, clean_to_filesystem)

        assert cert.is_ca is True
        assert cert.ski is not None
        assert cert.ski == ca_cert_data['ski']
        assert "CN=Test CA" in cert.subject

    def test_signed_certificate_with_aki(self, temp_cert_dir, signed_cert_data):
        """Test certificate signed by CA with AKI"""
        cert_file = temp_cert_dir / "signed.crt"
        cert_file.write_bytes(signed_cert_data['cert_pem'])

        clean_to_filesystem = {"signed.crt": "signed.crt"}

        cert = Certificate("signed.crt", "signed.crt", temp_cert_dir, clean_to_filesystem)

        assert cert.is_ca is False
        assert cert.aki is not None
        assert cert.aki == signed_cert_data['aki']
        assert "CN=signed.example.com" in cert.subject
        assert "CN=Test CA" in cert.issuer

    def test_certificate_without_ski_extension(self, temp_cert_dir):
        """Test certificate without SKI extension"""
        cert, _ = TestCertificateFixtures.create_basic_cert()
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        cert_file = temp_cert_dir / "no-ski.crt"
        cert_file.write_bytes(cert_pem)

        clean_to_filesystem = {"no-ski.crt": "no-ski.crt"}

        cert_obj = Certificate("no-ski.crt", "no-ski.crt", temp_cert_dir, clean_to_filesystem)

        assert cert_obj.ski is None

    def test_certificate_without_aki_extension(self, temp_cert_dir, basic_cert_data):
        """Test certificate without AKI extension (self-signed)"""
        cert_file = temp_cert_dir / "self-signed.crt"
        cert_file.write_bytes(basic_cert_data['cert_pem'])

        clean_to_filesystem = {"self-signed.crt": "self-signed.crt"}

        cert = Certificate("self-signed.crt", "self-signed.crt", temp_cert_dir, clean_to_filesystem)

        assert cert.aki is None

    def test_certificate_invalid_pem_data(self, temp_cert_dir):
        """Test handling of invalid certificate data"""
        cert_file = temp_cert_dir / "invalid.crt"
        cert_file.write_bytes(b"This is not a valid PEM certificate")

        clean_to_filesystem = {"invalid.crt": "invalid.crt"}

        with pytest.raises(ValueError, match="Failed to parse certificate invalid.crt"):
            Certificate("invalid.crt", "invalid.crt", temp_cert_dir, clean_to_filesystem)

    def test_certificate_file_not_found(self, temp_cert_dir):
        """Test handling of missing certificate file"""
        clean_to_filesystem = {"missing.crt": "missing.crt"}

        with pytest.raises(ValueError):
            Certificate("missing.crt", "missing.crt", temp_cert_dir, clean_to_filesystem)

    def test_certificate_repr(self, temp_cert_dir, basic_cert_data):
        """Test certificate string representation"""
        cert_file = temp_cert_dir / "repr-test.crt"
        cert_file.write_bytes(basic_cert_data['cert_pem'])

        clean_to_filesystem = {"repr-test.crt": "repr-test.crt"}

        cert = Certificate("repr-test.crt", "repr-test.crt", temp_cert_dir, clean_to_filesystem)

        repr_str = repr(cert)
        assert "Certificate Cert:" in repr_str
        assert "test.example.com" in repr_str
        assert "repr-test.crt" in repr_str
        assert "Exp:" in repr_str

    def test_ca_certificate_repr(self, temp_cert_dir, ca_cert_data):
        """Test CA certificate string representation"""
        cert_file = temp_cert_dir / "ca-repr.crt"
        cert_file.write_bytes(ca_cert_data['cert_pem'])

        clean_to_filesystem = {"ca-repr.crt": "ca-repr.crt"}

        cert = Certificate("ca-repr.crt", "ca-repr.crt", temp_cert_dir, clean_to_filesystem)

        repr_str = repr(cert)
        assert "Certificate CA:" in repr_str
        assert "Test CA" in repr_str

    def test_certificate_str_method(self, temp_cert_dir, basic_cert_data):
        """Test certificate __str__ method"""
        cert_file = temp_cert_dir / "str-test.crt"
        cert_file.write_bytes(basic_cert_data['cert_pem'])

        clean_to_filesystem = {"str-test.crt": "str-test.crt"}

        cert = Certificate("str-test.crt", "str-test.crt", temp_cert_dir, clean_to_filesystem)

        str_output = str(cert)
        assert cert.full_path in str_output
        assert "Certificate: str-test.crt" in str_output
        assert "Subject:" in str_output

    def test_certificate_hash_and_equality(self, temp_cert_dir, basic_cert_data):
        """Test certificate hashing and equality"""
        cert_file = temp_cert_dir / "hash-test.crt"
        cert_file.write_bytes(basic_cert_data['cert_pem'])

        clean_to_filesystem = {"hash-test.crt": "hash-test.crt"}

        cert1 = Certificate("hash-test.crt", "hash-test.crt", temp_cert_dir, clean_to_filesystem)
        cert2 = Certificate("hash-test.crt", "hash-test.crt", temp_cert_dir, clean_to_filesystem)

        # Same certificate data should be equal
        assert cert1 == cert2
        assert hash(cert1) == hash(cert2)

    def test_certificate_inequality_different_serial(self, temp_cert_dir):
        """Test certificate inequality with different serial numbers"""
        cert1, _ = TestCertificateFixtures.create_basic_cert(serial_number=12345)
        cert2, _ = TestCertificateFixtures.create_basic_cert(serial_number=67890)

        cert1_pem = cert1.public_bytes(serialization.Encoding.PEM)
        cert2_pem = cert2.public_bytes(serialization.Encoding.PEM)

        cert1_file = temp_cert_dir / "cert1.crt"
        cert2_file = temp_cert_dir / "cert2.crt"
        cert1_file.write_bytes(cert1_pem)
        cert2_file.write_bytes(cert2_pem)

        clean_to_filesystem = {
            "cert1.crt": "cert1.crt",
            "cert2.crt": "cert2.crt"
        }

        cert_obj1 = Certificate("cert1.crt", "cert1.crt", temp_cert_dir, clean_to_filesystem)
        cert_obj2 = Certificate("cert2.crt", "cert2.crt", temp_cert_dir, clean_to_filesystem)

        assert cert_obj1 != cert_obj2

    def test_certificate_inequality_different_type(self, temp_cert_dir, basic_cert_data):
        """Test certificate inequality with different object type"""
        cert_file = temp_cert_dir / "type-test.crt"
        cert_file.write_bytes(basic_cert_data['cert_pem'])

        clean_to_filesystem = {"type-test.crt": "type-test.crt"}

        cert = Certificate("type-test.crt", "type-test.crt", temp_cert_dir, clean_to_filesystem)

        assert cert != "not a certificate"
        assert cert != 42

    @patch('f5_config_parser.certificates.certificate.Certificate._discover_dependencies')
    def test_discover_dependencies_called(self, mock_discover, temp_cert_dir, basic_cert_data):
        """Test that dependency discovery can be called"""
        cert_file = temp_cert_dir / "deps-test.crt"
        cert_file.write_bytes(basic_cert_data['cert_pem'])

        clean_to_filesystem = {"deps-test.crt": "deps-test.crt"}

        cert = Certificate("deps-test.crt", "deps-test.crt", temp_cert_dir, clean_to_filesystem)

        # Mock the collection
        mock_collection = Mock()

        # Call the dependency discovery method
        cert._discover_dependencies(mock_collection)

        # Verify it was called
        mock_discover.assert_called_once_with(mock_collection)


class TestCertificateEdgeCases:
    """Test edge cases and error conditions"""

    @pytest.fixture
    def temp_cert_dir(self):
        """Create temporary directory for test certificates"""
        temp_dir = Path(tempfile.mkdtemp())
        yield temp_dir
        shutil.rmtree(temp_dir)

    def test_certificate_with_expired_date(self, temp_cert_dir):
        """Test certificate that's already expired"""
        cert, _ = TestCertificateFixtures.create_basic_cert(valid_days=-30)  # Expired 30 days ago
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        cert_file = temp_cert_dir / "expired.crt"
        cert_file.write_bytes(cert_pem)

        clean_to_filesystem = {"expired.crt": "expired.crt"}

        cert_obj = Certificate("expired.crt", "expired.crt", temp_cert_dir, clean_to_filesystem)

        assert cert_obj.not_valid_after < datetime.now(timezone.utc)

    def test_certificate_with_future_date(self, temp_cert_dir):
        """Test certificate that's not yet valid"""
        # Create certificate that becomes valid tomorrow
        private_key = TestCertificateFixtures.create_private_key()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "future.example.com"),
        ])

        future_date = datetime.now(timezone.utc) + timedelta(days=1)
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            future_date
        ).not_valid_after(
            future_date + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        cert_file = temp_cert_dir / "future.crt"
        cert_file.write_bytes(cert_pem)

        clean_to_filesystem = {"future.crt": "future.crt"}

        cert_obj = Certificate("future.crt", "future.crt", temp_cert_dir, clean_to_filesystem)

        assert cert_obj.not_valid_before > datetime.now(timezone.utc)

    def test_certificate_with_no_common_name(self, temp_cert_dir):
        """Test certificate without common name in subject"""
        private_key = TestCertificateFixtures.create_private_key()

        # Subject without CN
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AU"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org No CN"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        cert_file = temp_cert_dir / "no-cn.crt"
        cert_file.write_bytes(cert_pem)

        clean_to_filesystem = {"no-cn.crt": "no-cn.crt"}

        cert_obj = Certificate("no-cn.crt", "no-cn.crt", temp_cert_dir, clean_to_filesystem)

        # Should still work, just no CN in subject
        assert "O=Test Org No CN" in cert_obj.subject

        # __repr__ should handle missing CN gracefully
        repr_str = repr(cert_obj)
        assert "Unknown" in repr_str  # Should show "Unknown" when no CN found


# Sample usage for debugging - these won't print to console, just run
def sample_test_data():
    """Sample data for breakpoint debugging"""
    cert_data = TestCertificateFixtures.create_basic_cert()
    ca_data = TestCertificateFixtures.create_basic_cert(is_ca=True, subject_cn="Test CA")
    pass  # Put breakpoint here to inspect cert_data and ca_data


if __name__ == "__main__":
    sample_test_data()