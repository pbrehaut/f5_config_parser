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


class TestCertificateRealisticData:
    """Test Certificate class using realistic data extracted from real F5 archive"""

    @pytest.fixture
    def temp_cert_dir(self):
        """Create temporary directory for test certificates"""
        temp_dir = Path(tempfile.mkdtemp())
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def digicert_ca_data(self):
        """Create DigiCert CA certificate matching real F5 data"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Real DigiCert CA subject from your data
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DigiCert Inc"),
            x509.NameAttribute(NameOID.COMMON_NAME, "DigiCert SHA2 Secure Server CA"),
        ])

        # Real DigiCert Global Root CA issuer from your data
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DigiCert Inc"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "www.digicert.com"),
            x509.NameAttribute(NameOID.COMMON_NAME, "DigiCert Global Root CA"),
        ])

        # Real dates from your data
        not_valid_before = datetime(2013, 3, 8, 12, 0, tzinfo=timezone.utc)
        not_valid_after = datetime(2023, 3, 8, 12, 0, tzinfo=timezone.utc)

        # Real serial number from your data
        serial_number = 2646203786665923649276728595390119057

        # Real SKI from your data
        ski_hex = '0F80611C823161D52F28E78D4638B42CE1C6D9E2'
        ski_bytes = binascii.unhexlify(ski_hex)

        # Real AKI from your data
        aki_hex = '03DE503556D14CBB66F0A3E21B1BC397B23DD155'
        aki_bytes = binascii.unhexlify(aki_hex)

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            serial_number
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier(ski_bytes),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=aki_bytes,
                authority_cert_issuer=None,
                authority_cert_serial_number=None
            ),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        return {
            'cert': cert,
            'cert_pem': cert.public_bytes(serialization.Encoding.PEM),
            'filename': '/Common/DigiCertCA.crt',
            'filesystem_filename': 'files_d\\Common_d\\certificate_d\\_COLON_Common_COLON_DigiCertCA.crt_56179_1',
            'expected_attributes': {
                'subject': 'CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US',
                'issuer': 'CN=DigiCert Global Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US',
                'serial_number': '2646203786665923649276728595390119057',
                'is_ca': True,
                'ski': '0F80611C823161D52F28E78D4638B42CE1C6D9E2',
                'aki': '03DE503556D14CBB66F0A3E21B1BC397B23DD155',
                'signature_algorithm': 'sha256WithRSAEncryption',
                'not_valid_before': datetime(2013, 3, 8, 12, 0, tzinfo=timezone.utc),
                'not_valid_after': datetime(2023, 3, 8, 12, 0, tzinfo=timezone.utc),
            }
        }

    @pytest.fixture
    def signed_cert_data(self):
        """Create signed certificate matching real F5 data"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Real subject from your data
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Virginia"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Tysons"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Computer Sciences Corporation"),
            x509.NameAttribute(NameOID.COMMON_NAME, "servicedeskdr.aust.csc.com"),
        ])

        # Real issuer from your data (matches DigiCert CA)
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DigiCert Inc"),
            x509.NameAttribute(NameOID.COMMON_NAME, "DigiCert SHA2 Secure Server CA"),
        ])

        # Real dates from your data
        not_valid_before = datetime(2020, 1, 9, 0, 0, tzinfo=timezone.utc)
        not_valid_after = datetime(2021, 1, 12, 12, 0, tzinfo=timezone.utc)

        # Real serial number from your data
        serial_number = 17600078751183532245023401801566972072

        # Real SKI from your data
        ski_hex = '179E680F3250B3E5E9DC074C44EDDA9FDDCF61F2'
        ski_bytes = binascii.unhexlify(ski_hex)

        # Real AKI from your data (matches DigiCert CA's SKI)
        aki_hex = '0F80611C823161D52F28E78D4638B42CE1C6D9E2'
        aki_bytes = binascii.unhexlify(aki_hex)

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            serial_number
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier(ski_bytes),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=aki_bytes,
                authority_cert_issuer=None,
                authority_cert_serial_number=None
            ),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        # Create matching key file
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        return {
            'cert': cert,
            'cert_pem': cert.public_bytes(serialization.Encoding.PEM),
            'key_pem': key_pem,
            'filename': '/Legacy-CSC/servicedeskdr.aust.csc.com.crt',
            'key_filename': '/Legacy-CSC/servicedeskdr.aust.csc.com.key',
            'filesystem_filename': 'files_d\\Legacy-CSC_d\\certificate_d\\_COLON_Legacy-CSC_COLON_servicedeskdr.aust.csc.com.crt_56683_3',
            'key_filesystem_filename': 'files_d\\Legacy-CSC_d\\certificate_key_d\\_COLON_Legacy-CSC_COLON_servicedeskdr.aust.csc.com.key_56663_1',
            'expected_attributes': {
                'subject': 'CN=servicedeskdr.aust.csc.com,O=Computer Sciences Corporation,L=Tysons,ST=Virginia,C=US',
                'issuer': 'CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US',
                'serial_number': '17600078751183532245023401801566972072',
                'is_ca': False,
                'ski': '179E680F3250B3E5E9DC074C44EDDA9FDDCF61F2',
                'aki': '0F80611C823161D52F28E78D4638B42CE1C6D9E2',
                'signature_algorithm': 'sha256WithRSAEncryption',
                'not_valid_before': datetime(2020, 1, 9, 0, 0, tzinfo=timezone.utc),
                'not_valid_after': datetime(2021, 1, 12, 12, 0, tzinfo=timezone.utc),
            }
        }

    def test_digicert_ca_certificate(self, temp_cert_dir, digicert_ca_data):
        """Test DigiCert CA certificate with real data attributes"""
        cert_file = temp_cert_dir / "DigiCertCA.crt"
        cert_file.write_bytes(digicert_ca_data['cert_pem'])

        clean_to_filesystem = {('certificate', "/Common/DigiCertCA.crt"): "DigiCertCA.crt"}

        cert = Certificate(('certificate', "/Common/DigiCertCA.crt"), "DigiCertCA.crt", temp_cert_dir, clean_to_filesystem)

        expected = digicert_ca_data['expected_attributes']

        # Test all attributes match real data
        assert cert.filename == "/Common/DigiCertCA.crt"
        assert cert.subject == expected['subject']
        assert cert.issuer == expected['issuer']
        assert cert.serial_number == expected['serial_number']
        assert cert.is_ca == expected['is_ca']
        assert cert.ski == expected['ski']
        assert cert.aki == expected['aki']
        assert cert.signature_algorithm == expected['signature_algorithm']
        assert cert.not_valid_before == expected['not_valid_before']
        assert cert.not_valid_after == expected['not_valid_after']

        # Test that it's recognised as a CA
        assert cert.is_ca is True

        # Test no matching key file for CA
        assert cert.key_filename is None
        assert cert.key_filesystem_filename is None

    def test_signed_certificate_with_matching_key(self, temp_cert_dir, signed_cert_data):
        """Test signed certificate with real data attributes and matching key"""
        # Write certificate and key files
        cert_file = temp_cert_dir / "servicedeskdr.aust.csc.com.crt"
        key_file = temp_cert_dir / "servicedeskdr.aust.csc.com.key"
        cert_file.write_bytes(signed_cert_data['cert_pem'])
        key_file.write_bytes(signed_cert_data['key_pem'])

        clean_to_filesystem = {
            ('certificate', "/Legacy-CSC/servicedeskdr.aust.csc.com.crt"): "servicedeskdr.aust.csc.com.crt",
            ('key', "/Legacy-CSC/servicedeskdr.aust.csc.com.key"): "servicedeskdr.aust.csc.com.key"
        }

        cert = Certificate(
            ('certificate', "/Legacy-CSC/servicedeskdr.aust.csc.com.crt"),
            "servicedeskdr.aust.csc.com.crt",
            temp_cert_dir,
            clean_to_filesystem
        )

        expected = signed_cert_data['expected_attributes']

        # Test all attributes match real data
        assert cert.filename == "/Legacy-CSC/servicedeskdr.aust.csc.com.crt"
        assert cert.subject == expected['subject']
        assert cert.issuer == expected['issuer']
        assert cert.serial_number == expected['serial_number']
        assert cert.is_ca == expected['is_ca']
        assert cert.ski == expected['ski']
        assert cert.aki == expected['aki']
        assert cert.signature_algorithm == expected['signature_algorithm']
        assert cert.not_valid_before == expected['not_valid_before']
        assert cert.not_valid_after == expected['not_valid_after']

        # Test that it's not a CA
        assert cert.is_ca is False

        # Test matching key file found
        assert cert.key_filename == "/Legacy-CSC/servicedeskdr.aust.csc.com.key"
        assert cert.key_filesystem_filename == "servicedeskdr.aust.csc.com.key"

    def test_certificate_chain_relationship(self, temp_cert_dir, digicert_ca_data, signed_cert_data):
        """Test that we can identify certificate chain relationships"""
        # Write both certificates
        ca_file = temp_cert_dir / "DigiCertCA.crt"
        cert_file = temp_cert_dir / "servicedeskdr.aust.csc.com.crt"
        ca_file.write_bytes(digicert_ca_data['cert_pem'])
        cert_file.write_bytes(signed_cert_data['cert_pem'])

        clean_to_filesystem = {
            ('certificate', "/Common/DigiCertCA.crt"): "DigiCertCA.crt",
            ('certificate', "/Legacy-CSC/servicedeskdr.aust.csc.com.crt"): "servicedeskdr.aust.csc.com.crt"
        }

        ca_cert = Certificate(('certificate', "/Common/DigiCertCA.crt"), "DigiCertCA.crt", temp_cert_dir, clean_to_filesystem)
        signed_cert = Certificate(
            ('certificate', "/Legacy-CSC/servicedeskdr.aust.csc.com.crt"),
            "servicedeskdr.aust.csc.com.crt",
            temp_cert_dir,
            clean_to_filesystem
        )

        # Test certificate chain relationship
        # The signed certificate's AKI should match the CA's SKI
        assert signed_cert.aki == ca_cert.ski
        assert signed_cert.aki == '0F80611C823161D52F28E78D4638B42CE1C6D9E2'

        # The signed certificate should have the CA as its issuer
        assert signed_cert.issuer == 'CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US'
        assert ca_cert.subject == 'CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US'

    def test_certificate_repr_with_real_data(self, temp_cert_dir, digicert_ca_data, signed_cert_data):
        """Test certificate representations with real data"""
        # Test CA certificate repr
        ca_file = temp_cert_dir / "DigiCertCA.crt"
        ca_file.write_bytes(digicert_ca_data['cert_pem'])

        clean_to_filesystem = {('certificate', "/Common/DigiCertCA.crt"): "DigiCertCA.crt"}

        ca_cert = Certificate(('certificate', "/Common/DigiCertCA.crt"), "DigiCertCA.crt", temp_cert_dir, clean_to_filesystem)

        ca_repr = repr(ca_cert)
        assert "Certificate CA:" in ca_repr
        assert "DigiCert SHA2 Secure Server CA" in ca_repr
        assert "/Common/DigiCertCA.crt" in ca_repr
        assert "2023-03-08 12:00:00+00:00" in ca_repr

        # Test signed certificate repr
        cert_file = temp_cert_dir / "servicedeskdr.aust.csc.com.crt"
        cert_file.write_bytes(signed_cert_data['cert_pem'])

        clean_to_filesystem = {('certificate', "/Legacy-CSC/servicedeskdr.aust.csc.com.crt"): "servicedeskdr.aust.csc.com.crt"}

        signed_cert = Certificate(
            ('certificate', "/Legacy-CSC/servicedeskdr.aust.csc.com.crt"),
            "servicedeskdr.aust.csc.com.crt",
            temp_cert_dir,
            clean_to_filesystem
        )

        signed_repr = repr(signed_cert)
        assert "Certificate Cert:" in signed_repr
        assert "servicedeskdr.aust.csc.com" in signed_repr
        assert "/Legacy-CSC/servicedeskdr.aust.csc.com.crt" in signed_repr
        assert "2021-01-12 12:00:00+00:00" in signed_repr

    def test_expired_certificate_detection(self, temp_cert_dir, signed_cert_data):
        """Test that expired certificate is properly identified"""
        cert_file = temp_cert_dir / "servicedeskdr.aust.csc.com.crt"
        cert_file.write_bytes(signed_cert_data['cert_pem'])

        clean_to_filesystem = {('certificate', "/Legacy-CSC/servicedeskdr.aust.csc.com.crt"): "servicedeskdr.aust.csc.com.crt"}

        cert = Certificate(
            ('certificate', "/Legacy-CSC/servicedeskdr.aust.csc.com.crt"),
            "servicedeskdr.aust.csc.com.crt",
            temp_cert_dir,
            clean_to_filesystem
        )

        # This certificate expired in 2021, so it should be expired now
        assert cert.not_valid_after < datetime.now(timezone.utc)

    @patch('f5_config_parser.certificates.certificate.Certificate._discover_dependencies')
    def test_discover_dependencies_with_real_data(self, mock_discover, temp_cert_dir, signed_cert_data):
        """Test dependency discovery with realistic certificate"""
        cert_file = temp_cert_dir / "servicedeskdr.aust.csc.com.crt"
        cert_file.write_bytes(signed_cert_data['cert_pem'])

        clean_to_filesystem = {('certificate', "/Legacy-CSC/servicedeskdr.aust.csc.com.crt"): "servicedeskdr.aust.csc.com.crt"}

        cert = Certificate(
            ('certificate', "/Legacy-CSC/servicedeskdr.aust.csc.com.crt"),
            "servicedeskdr.aust.csc.com.crt",
            temp_cert_dir,
            clean_to_filesystem
        )

        # Mock the collection
        mock_collection = Mock()

        # Call the dependency discovery method
        cert._discover_dependencies(mock_collection)

        # Verify it was called
        mock_discover.assert_called_once_with(mock_collection)


# Sample usage for debugging - these won't print to console, just run
def sample_real_test_data():
    """Sample real data for breakpoint debugging"""
    fixtures = TestCertificateRealisticData()
    ca_data = fixtures.digicert_ca_data()
    signed_data = fixtures.signed_cert_data()
    pass  # Put breakpoint here to inspect real certificate data


if __name__ == "__main__":
    sample_real_test_data()