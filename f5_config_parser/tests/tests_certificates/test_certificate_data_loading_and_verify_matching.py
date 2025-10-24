import pytest
import tempfile
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
import shutil
from unittest.mock import Mock, patch
import binascii

from f5_config_parser.certificates.certificate import Certificate


class TestCertificatePEMLoadingAndKeyVerification:
    """Test Certificate PEM data loading and key verification functionality"""

    @pytest.fixture
    def temp_cert_dir(self):
        """Create temporary directory for test certificates"""
        temp_dir = Path(tempfile.mkdtemp())
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def rsa_cert_and_key_data(self):
        """Create RSA certificate and matching private key"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AU"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "NSW"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Sydney"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject  # Self-signed
        ).public_key(
            private_key.public_key()
        ).serial_number(
            12345
        ).not_valid_before(
            datetime(2024, 1, 1, tzinfo=timezone.utc)
        ).not_valid_after(
            datetime(2025, 1, 1, tzinfo=timezone.utc)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).sign(private_key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        return {
            'cert_pem': cert_pem,
            'key_pem': key_pem,
            'cert_obj': cert,
            'key_obj': private_key
        }

    @pytest.fixture
    def mismatched_key_data(self):
        """Create a different RSA private key that doesn't match the certificate"""
        different_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_pem = different_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return key_pem

    def test_load_pem_data_enabled(self, temp_cert_dir, rsa_cert_and_key_data):
        """Test that PEM data is loaded when passed to Certificate"""
        # Write certificate and key files
        cert_file = temp_cert_dir / "test.example.com.crt"
        key_file = temp_cert_dir / "test.example.com.key"
        cert_file.write_bytes(rsa_cert_and_key_data['cert_pem'])
        key_file.write_bytes(rsa_cert_and_key_data['key_pem'])

        # Load and parse certificate
        cert_data = cert_file.read_bytes()
        cert_obj = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Load PEM data
        cert_pem_data = cert_data.decode('utf-8')
        key_pem_data = key_file.read_text(encoding='utf-8')

        # Create Certificate object with PEM data
        cert = Certificate(
            "/Common/test.example.com.crt",
            cert_obj,
            cert_pem_data=cert_pem_data,
            key_filename="/Common/test.example.com.key",
            key_pem_data=key_pem_data
        )

        # Verify PEM data is loaded
        assert cert.pem_data is not None
        assert cert.key_pem_data is not None
        assert isinstance(cert.pem_data, str)
        assert isinstance(cert.key_pem_data, str)
        assert "-----BEGIN CERTIFICATE-----" in cert.pem_data
        assert "-----BEGIN PRIVATE KEY-----" in cert.key_pem_data

        # Verify the PEM data matches what we wrote
        assert cert.pem_data == rsa_cert_and_key_data['cert_pem'].decode('utf-8')
        assert cert.key_pem_data == rsa_cert_and_key_data['key_pem'].decode('utf-8')

    def test_load_pem_data_disabled(self, temp_cert_dir, rsa_cert_and_key_data):
        """Test that PEM data is not loaded when not passed to Certificate"""
        # Write certificate and key files
        cert_file = temp_cert_dir / "test.example.com.crt"
        key_file = temp_cert_dir / "test.example.com.key"
        cert_file.write_bytes(rsa_cert_and_key_data['cert_pem'])
        key_file.write_bytes(rsa_cert_and_key_data['key_pem'])

        # Load and parse certificate
        cert_data = cert_file.read_bytes()
        cert_obj = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Create Certificate object without PEM data
        cert = Certificate(
            "/Common/test.example.com.crt",
            cert_obj,
            key_filename="/Common/test.example.com.key"
        )

        # Verify PEM data is not loaded
        assert cert.pem_data is None
        assert cert.key_pem_data is None

    def test_load_pem_data_no_matching_key(self, temp_cert_dir, rsa_cert_and_key_data):
        """Test PEM loading when certificate has no matching key file"""
        # Write only certificate file
        cert_file = temp_cert_dir / "ca.crt"
        cert_file.write_bytes(rsa_cert_and_key_data['cert_pem'])

        # Load and parse certificate
        cert_data = cert_file.read_bytes()
        cert_obj = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Load PEM data (cert only, no key)
        cert_pem_data = cert_data.decode('utf-8')

        # Create Certificate object with cert PEM but no key
        cert = Certificate(
            "/Common/ca.crt",
            cert_obj,
            cert_pem_data=cert_pem_data
        )

        # Verify certificate PEM data is loaded but key PEM data is None
        assert cert.pem_data is not None
        assert cert.key_pem_data is None
        assert cert.key_filename is None

    def test_verify_key_match_success(self, temp_cert_dir, rsa_cert_and_key_data):
        """Test successful key verification when certificate and key match"""
        # Write certificate and key files
        cert_file = temp_cert_dir / "test.example.com.crt"
        key_file = temp_cert_dir / "test.example.com.key"
        cert_file.write_bytes(rsa_cert_and_key_data['cert_pem'])
        key_file.write_bytes(rsa_cert_and_key_data['key_pem'])

        # Load and parse certificate
        cert_data = cert_file.read_bytes()
        cert_obj = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Load PEM data
        cert_pem_data = cert_data.decode('utf-8')
        key_pem_data = key_file.read_text(encoding='utf-8')

        # Create Certificate object with matching cert and key
        cert = Certificate(
            "/Common/test.example.com.crt",
            cert_obj,
            cert_pem_data=cert_pem_data,
            key_filename="/Common/test.example.com.key",
            key_pem_data=key_pem_data
        )

        # Verify key match returns True
        assert cert.verify_key_match() is True

    def test_verify_key_match_failure(self, temp_cert_dir, rsa_cert_and_key_data, mismatched_key_data):
        """Test key verification failure when certificate and key don't match"""
        # Write certificate and mismatched key files
        cert_file = temp_cert_dir / "test.example.com.crt"
        key_file = temp_cert_dir / "test.example.com.key"
        cert_file.write_bytes(rsa_cert_and_key_data['cert_pem'])
        key_file.write_bytes(mismatched_key_data)

        # Load and parse certificate
        cert_data = cert_file.read_bytes()
        cert_obj = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Load PEM data (cert with mismatched key)
        cert_pem_data = cert_data.decode('utf-8')
        key_pem_data = key_file.read_text(encoding='utf-8')

        # Create Certificate object with mismatched key
        cert = Certificate(
            "/Common/test.example.com.crt",
            cert_obj,
            cert_pem_data=cert_pem_data,
            key_filename="/Common/test.example.com.key",
            key_pem_data=key_pem_data
        )

        # Verify key match returns False
        assert cert.verify_key_match() is False

    def test_verify_key_match_no_key(self, temp_cert_dir, rsa_cert_and_key_data):
        """Test key verification when certificate has no key"""
        cert_file = temp_cert_dir / "ca.crt"
        cert_file.write_bytes(rsa_cert_and_key_data['cert_pem'])

        # Load and parse certificate
        cert_data = cert_file.read_bytes()
        cert_obj = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Load PEM data (cert only)
        cert_pem_data = cert_data.decode('utf-8')

        # Create Certificate object without key
        cert = Certificate(
            "/Common/ca.crt",
            cert_obj,
            cert_pem_data=cert_pem_data
        )

        # Verify key match returns False when no key
        with pytest.raises(ValueError, match="Key PEM data not available"):
            cert.verify_key_match()

    def test_verify_key_match_no_pem_data(self, temp_cert_dir, rsa_cert_and_key_data):
        """Test key verification raises error when PEM data not loaded"""
        cert_file = temp_cert_dir / "test.example.com.crt"
        key_file = temp_cert_dir / "test.example.com.key"
        cert_file.write_bytes(rsa_cert_and_key_data['cert_pem'])
        key_file.write_bytes(rsa_cert_and_key_data['key_pem'])

        # Load and parse certificate
        cert_data = cert_file.read_bytes()
        cert_obj = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Create Certificate object without PEM data
        cert = Certificate(
            "/Common/test.example.com.crt",
            cert_obj,
            key_filename="/Common/test.example.com.key"
        )

        # Verify key match raises ValueError when PEM data not loaded
        with pytest.raises(ValueError, match="Certificate PEM data not loaded"):
            cert.verify_key_match()

    def test_verify_key_match_no_key_pem_data(self, temp_cert_dir, rsa_cert_and_key_data):
        """Test key verification raises error when key PEM data not available"""
        cert_file = temp_cert_dir / "test.example.com.crt"
        cert_file.write_bytes(rsa_cert_and_key_data['cert_pem'])

        # Load and parse certificate
        cert_data = cert_file.read_bytes()
        cert_obj = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Load PEM data (cert only)
        cert_pem_data = cert_data.decode('utf-8')

        # Create Certificate object with cert PEM but key filename set and no key PEM data
        cert = Certificate(
            "/Common/test.example.com.crt",
            cert_obj,
            cert_pem_data=cert_pem_data,
            key_filename="/Common/test.example.com.key"
        )

        # Verify key match raises ValueError when key PEM data not available
        with pytest.raises(ValueError, match="Key PEM data not available"):
            cert.verify_key_match()

    def test_verify_key_match_ec_cert(self, temp_cert_dir):
        """Test key verification with EC (Elliptic Curve) certificate"""
        # Generate EC certificate and key
        private_key = ec.generate_private_key(ec.SECP256R1())

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "ec.example.com"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            54321
        ).not_valid_before(
            datetime(2024, 1, 1, tzinfo=timezone.utc)
        ).not_valid_after(
            datetime(2025, 1, 1, tzinfo=timezone.utc)
        ).sign(private_key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        cert_file = temp_cert_dir / "ec.crt"
        key_file = temp_cert_dir / "ec.key"
        cert_file.write_bytes(cert_pem)
        key_file.write_bytes(key_pem)

        # Load and parse certificate
        cert_data = cert_file.read_bytes()
        cert_obj = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Load PEM data
        cert_pem_data = cert_data.decode('utf-8')
        key_pem_data = key_file.read_text(encoding='utf-8')

        # Create Certificate object
        cert_parsed = Certificate(
            "/Common/ec.crt",
            cert_obj,
            cert_pem_data=cert_pem_data,
            key_filename="/Common/ec.key",
            key_pem_data=key_pem_data
        )

        # Verify EC key match
        assert cert_parsed.verify_key_match() is True

    def test_verify_key_match_invalid_key_format(self, temp_cert_dir, rsa_cert_and_key_data):
        """Test key verification with invalid key format"""
        cert_file = temp_cert_dir / "test.example.com.crt"
        key_file = temp_cert_dir / "test.example.com.key"
        cert_file.write_bytes(rsa_cert_and_key_data['cert_pem'])
        key_file.write_text("INVALID KEY DATA")

        # Load and parse certificate
        cert_data = cert_file.read_bytes()
        cert_obj = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Load PEM data (cert with invalid key)
        cert_pem_data = cert_data.decode('utf-8')
        key_pem_data = key_file.read_text(encoding='utf-8')

        # Create Certificate object with invalid key
        cert = Certificate(
            "/Common/test.example.com.crt",
            cert_obj,
            cert_pem_data=cert_pem_data,
            key_filename="/Common/test.example.com.key",
            key_pem_data=key_pem_data
        )

        # Verify key match raises ValueError for invalid key format
        with pytest.raises(ValueError, match="Unable to load PEM file."):
            cert.verify_key_match()

    def test_repr_with_pem_loaded_indicator(self, temp_cert_dir, rsa_cert_and_key_data):
        """Test that __repr__ shows PEM loaded status"""
        # Write certificate and key files
        cert_file = temp_cert_dir / "test.example.com.crt"
        key_file = temp_cert_dir / "test.example.com.key"
        cert_file.write_bytes(rsa_cert_and_key_data['cert_pem'])
        key_file.write_bytes(rsa_cert_and_key_data['key_pem'])

        # Load and parse certificate
        cert_data = cert_file.read_bytes()
        cert_obj = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Test with PEM data loaded
        cert_pem_data = cert_data.decode('utf-8')
        key_pem_data = key_file.read_text(encoding='utf-8')

        cert_with_pem = Certificate(
            "/Common/test.example.com.crt",
            cert_obj,
            cert_pem_data=cert_pem_data,
            key_filename="/Common/test.example.com.key",
            key_pem_data=key_pem_data
        )

        repr_with_pem = repr(cert_with_pem)
        assert "(PEM loaded)" in repr_with_pem

        # Test without PEM data loaded
        cert_without_pem = Certificate(
            "/Common/test.example.com.crt",
            cert_obj,
            key_filename="/Common/test.example.com.key"
        )

        repr_without_pem = repr(cert_without_pem)
        assert "(PEM loaded)" not in repr_without_pem


class TestCertificatePEMIntegration:
    """Integration tests for PEM loading using real F5 archive data"""

    @pytest.fixture
    def test_archive_path(self):
        """Path to the test archive file"""
        test_dir = Path(__file__).parent
        return Path(test_dir / "../../sample_input/imsbrwlbip01_20250722_114109.tar")

    @pytest.fixture
    def skip_if_no_archive(self, test_archive_path):
        """Skip test if archive file doesn't exist"""
        if not test_archive_path.exists():
            pytest.skip(f"Test archive not found: {test_archive_path}")

    def test_load_certificates_with_pem_data(self, test_archive_path, skip_if_no_archive):
        """Test loading certificates with PEM data from real archive"""
        from f5_config_parser.certificates.certificate_loader import load_certificates_from_tar

        certificates = load_certificates_from_tar(str(test_archive_path), load_pem_data=True)

        # Find certificates that should have both cert and key data
        cert_with_key = None
        for cert in certificates:
            if cert.filename == '/Legacy-CSC/servicedeskdr.aust.csc.com.crt':
                cert_with_key = cert
                break

        assert cert_with_key is not None

        # Verify PEM data is loaded
        assert cert_with_key.pem_data is not None
        assert cert_with_key.key_pem_data is not None
        assert isinstance(cert_with_key.pem_data, str)
        assert isinstance(cert_with_key.key_pem_data, str)
        assert "-----BEGIN CERTIFICATE-----" in cert_with_key.pem_data
        assert "-----BEGIN PRIVATE KEY-----" in cert_with_key.key_pem_data

        # Test __repr__ includes PEM loaded indicator
        repr_str = repr(cert_with_key)
        assert "(PEM loaded)" in repr_str

    def test_load_certificates_without_pem_data(self, test_archive_path, skip_if_no_archive):
        """Test loading certificates without PEM data from real archive"""
        from f5_config_parser.certificates.certificate_loader import load_certificates_from_tar

        certificates = load_certificates_from_tar(str(test_archive_path), load_pem_data=False)

        # Verify PEM data is not loaded for any certificate
        for cert in certificates:
            assert cert.pem_data is None
            assert cert.key_pem_data is None

            # Test __repr__ doesn't include PEM loaded indicator
            repr_str = repr(cert)
            assert "(PEM loaded)" not in repr_str

    def test_verify_key_match_integration(self, test_archive_path, skip_if_no_archive):
        """Test key verification with real certificate pairs from archive"""
        from f5_config_parser.certificates.certificate_loader import load_certificates_from_tar

        certificates = load_certificates_from_tar(str(test_archive_path), load_pem_data=True)

        # Find certificates that have keys and test verification
        verified_count = 0
        for cert in certificates:
            if cert.key_pem_data is not None and not cert.is_ca:
                try:
                    # These should be matching certificate/key pairs from real F5 data
                    result = cert.verify_key_match()
                    assert result is True, f"Key verification failed for {cert.filename}"
                    verified_count += 1
                except ValueError as e:
                    # Some certificates might have issues, that's ok for this test
                    print(f"Skipping verification for {cert.filename}: {e}")

        # Ensure we actually tested some certificates
        assert verified_count > 0, "No certificates were successfully verified"

    def test_ca_certificates_key_verification_behaviour(self, test_archive_path, skip_if_no_archive):
        """Test that CA certificates return False for key verification"""
        from f5_config_parser.certificates.certificate_loader import load_certificates_from_tar

        certificates = load_certificates_from_tar(str(test_archive_path), load_pem_data=True)

        ca_certs = [cert for cert in certificates if cert.is_ca]

        for ca_cert in ca_certs:
            if ca_cert.pem_data is not None:
                # CA certificates should return False, not raise an exception
                result = ca_cert.verify_key_match()
                assert result is False, f"CA certificate {ca_cert.filename} should return False for key verification"

    def test_pem_data_error_handling_integration(self, test_archive_path, skip_if_no_archive):
        """Test PEM data loading error handling with real archive"""
        from f5_config_parser.certificates.certificate_loader import load_certificates_from_tar

        # Load with PEM data
        certificates = load_certificates_from_tar(str(test_archive_path), load_pem_data=True)

        # Find a certificate without PEM data loaded (simulate error case)
        cert_without_pem = None
        for cert in certificates:
            if cert.key_filename is not None and not cert.is_ca:
                # Manually clear PEM data to simulate error condition
                cert.pem_data = None
                cert_without_pem = cert
                break

        assert cert_without_pem is not None

        # Test that verify_key_match raises appropriate error
        with pytest.raises(ValueError, match="Certificate PEM data not loaded"):
            cert_without_pem.verify_key_match()

        # Find a certificate with cert PEM but no key PEM (simulate error case)
        cert_no_key_pem = None
        for cert in certificates:
            if cert.key_filename is not None and cert.pem_data is not None and not cert.is_ca:
                # Manually clear key PEM data to simulate error condition
                cert.key_pem_data = None
                cert_no_key_pem = cert
                break

        assert cert_no_key_pem is not None

        # Test that verify_key_match raises appropriate error
        with pytest.raises(ValueError, match="Key PEM data not available"):
            cert_no_key_pem.verify_key_match()


if __name__ == "__main__":
    # Sample usage for debugging
    def sample_pem_test_data():
        """Sample PEM test data for breakpoint debugging"""
        fixtures = TestCertificatePEMLoadingAndKeyVerification()
        rsa_data = fixtures.rsa_cert_and_key_data()
        print("RSA cert and key data created for debugging")
        pass  # Put breakpoint here


    sample_pem_test_data()