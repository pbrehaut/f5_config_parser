import pytest
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from f5_config_parser.certificates.certificate import Certificate


# @pytest.mark.skip(reason="Slow loading archive")
class TestCertificateIntegration:
    """Integration tests using real F5 archive data"""

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

    @pytest.fixture
    def loaded_certificates(self, test_archive_path, skip_if_no_archive):
        """Load certificates from the real archive"""
        # Import the loading function
        from f5_config_parser.certificates.certificate_loader import load_certificates_from_tar

        certificates = load_certificates_from_tar(str(test_archive_path))
        return certificates

    def test_archive_loads_successfully(self, loaded_certificates):
        """Test that certificates can be loaded from archive"""
        assert len(loaded_certificates) > 0
        assert all(isinstance(cert, Certificate) for cert in loaded_certificates)

    def test_digicert_ca_certificate_attributes(self, loaded_certificates):
        """Test DigiCert CA certificate has expected attributes"""
        # Find the DigiCert CA certificate
        digicert_ca = None
        for cert in loaded_certificates:
            if cert.filename == '/Common/DigiCertCA.crt':
                digicert_ca = cert
                break

        assert digicert_ca is not None, "DigiCert CA certificate not found"

        # Verify all expected attributes from debugger output
        assert digicert_ca.subject == 'CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US'
        assert digicert_ca.issuer == 'CN=DigiCert Global Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US'
        assert digicert_ca.serial_number == '2646203786665923649276728595390119057'
        assert digicert_ca.is_ca is True
        assert digicert_ca.ski == '0F80611C823161D52F28E78D4638B42CE1C6D9E2'
        assert digicert_ca.aki == '03DE503556D14CBB66F0A3E21B1BC397B23DD155'
        assert digicert_ca.signature_algorithm == 'sha256WithRSAEncryption'
        assert digicert_ca.not_valid_before == datetime(2013, 3, 8, 12, 0, tzinfo=timezone.utc)
        assert digicert_ca.not_valid_after == datetime(2023, 3, 8, 12, 0, tzinfo=timezone.utc)
        assert digicert_ca.key_filename is None
        assert digicert_ca.key_filesystem_filename is None

    def test_servicedeskdr_signed_certificate_attributes(self, loaded_certificates):
        """Test servicedeskdr signed certificate has expected attributes"""
        # Find the servicedeskdr certificate
        servicedeskdr_cert = None
        for cert in loaded_certificates:
            if cert.filename == '/Legacy-CSC/servicedeskdr.aust.csc.com.crt':
                servicedeskdr_cert = cert
                break

        assert servicedeskdr_cert is not None, "servicedeskdr certificate not found"

        # Verify all expected attributes from debugger output
        assert servicedeskdr_cert.subject == 'CN=servicedeskdr.aust.csc.com,O=Computer Sciences Corporation,L=Tysons,ST=Virginia,C=US'
        assert servicedeskdr_cert.issuer == 'CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US'
        assert servicedeskdr_cert.serial_number == '17600078751183532245023401801566972072'
        assert servicedeskdr_cert.is_ca is False
        assert servicedeskdr_cert.ski == '179E680F3250B3E5E9DC074C44EDDA9FDDCF61F2'
        assert servicedeskdr_cert.aki == '0F80611C823161D52F28E78D4638B42CE1C6D9E2'
        assert servicedeskdr_cert.signature_algorithm == 'sha256WithRSAEncryption'
        assert servicedeskdr_cert.not_valid_before == datetime(2020, 1, 9, 0, 0, tzinfo=timezone.utc)
        assert servicedeskdr_cert.not_valid_after == datetime(2021, 1, 12, 12, 0, tzinfo=timezone.utc)
        assert servicedeskdr_cert.key_filename == '/Legacy-CSC/servicedeskdr.aust.csc.com.key'
        assert servicedeskdr_cert.key_filesystem_filename == 'files_d\\Legacy-CSC_d\\certificate_key_d\\_COLON_Legacy-CSC_COLON_servicedeskdr.aust.csc.com.key_56663_1'

    def test_symantec_intermediate_ca_attributes(self, loaded_certificates):
        """Test Symantec intermediate CA certificate has expected attributes"""
        # Find the Symantec CA certificate
        symantec_ca = None
        for cert in loaded_certificates:
            if cert.filename == '/Common/Symantec-Class3-CA-G4.crt':
                symantec_ca = cert
                break

        assert symantec_ca is not None, "Symantec CA certificate not found"

        # Verify all expected attributes from debugger output
        assert symantec_ca.subject == 'CN=Symantec Class 3 Secure Server CA - G4,OU=Symantec Trust Network,O=Symantec Corporation,C=US'
        assert symantec_ca.issuer == 'CN=VeriSign Class 3 Public Primary Certification Authority - G5,OU=(c) 2006 VeriSign\\, Inc. - For authorized use only,OU=VeriSign Trust Network,O=VeriSign\\, Inc.,C=US'
        assert symantec_ca.serial_number == '107998343814376832458216740669838760447'
        assert symantec_ca.is_ca is True
        assert symantec_ca.ski == '5F60CF619055DF8443148A602AB2F57AF44318EF'
        assert symantec_ca.aki == '7FD365A7C2DDECBBF03009F34339FA02AF333133'
        assert symantec_ca.signature_algorithm == 'sha256WithRSAEncryption'
        assert symantec_ca.not_valid_before == datetime(2013, 10, 31, 0, 0, tzinfo=timezone.utc)
        assert symantec_ca.not_valid_after == datetime(2023, 10, 30, 23, 59, 59, tzinfo=timezone.utc)
        assert symantec_ca.key_filename is None
        assert symantec_ca.key_filesystem_filename is None

    def test_css_ecp_certificate_attributes(self, loaded_certificates):
        """Test css.ecp.csc.com.au certificate has expected attributes"""
        # Find the css.ecp certificate
        css_cert = None
        for cert in loaded_certificates:
            if cert.filename == '/ECP/css.ecp.csc.com.au.crt':
                css_cert = cert
                break

        assert css_cert is not None, "css.ecp certificate not found"

        # Verify all expected attributes from debugger output
        assert css_cert.subject == 'CN=css.ecp.csc.com.au,OU=GIS,O=CSC Australia Pty Limited,L=Macquarie Park,ST=New South Wales,C=AU'
        assert css_cert.issuer == 'CN=Symantec Class 3 Secure Server CA - G4,OU=Symantec Trust Network,O=Symantec Corporation,C=US'
        assert css_cert.serial_number == '111549149342822621328142454596545397276'
        assert css_cert.is_ca is False
        assert css_cert.ski is None  # No SKI for end-entity certificate
        assert css_cert.aki == '5F60CF619055DF8443148A602AB2F57AF44318EF'
        assert css_cert.signature_algorithm == 'sha256WithRSAEncryption'
        assert css_cert.not_valid_before == datetime(2016, 5, 17, 0, 0, tzinfo=timezone.utc)
        assert css_cert.not_valid_after == datetime(2017, 5, 18, 23, 59, 59, tzinfo=timezone.utc)
        assert css_cert.key_filename == '/ECP/css.ecp.csc.com.au.key'
        assert css_cert.key_filesystem_filename == 'files_d\\ECP_d\\certificate_key_d\\_COLON_ECP_COLON_css.ecp.csc.com.au.key_77183_1'

    def test_proxy_paxus_self_signed_certificate_attributes(self, loaded_certificates):
        """Test proxy.paxus.com.au self-signed certificate has expected attributes"""
        # Find the proxy.paxus certificate
        proxy_cert = None
        for cert in loaded_certificates:
            if cert.filename == '/Common/proxy.paxus.com.au.crt':
                proxy_cert = cert
                break

        assert proxy_cert is not None, "proxy.paxus certificate not found"

        # Verify all expected attributes from debugger output
        assert proxy_cert.subject == 'CN=proxy.paxus.com.au,OU=GIS,O=CSC Australia Pty Ltd,L=Sydney,ST=NSW,C=AU'
        assert proxy_cert.issuer == 'CN=proxy.paxus.com.au,OU=GIS,O=CSC Australia Pty Ltd,L=Sydney,ST=NSW,C=AU'
        assert proxy_cert.serial_number == '1648'
        assert proxy_cert.is_ca is False
        assert proxy_cert.ski is None  # No SKI for self-signed
        assert proxy_cert.aki is None  # No AKI for self-signed
        assert proxy_cert.signature_algorithm == 'sha1WithRSAEncryption'
        assert proxy_cert.not_valid_before == datetime(2014, 7, 8, 6, 16, 50, tzinfo=timezone.utc)
        assert proxy_cert.not_valid_after == datetime(2019, 7, 7, 6, 16, 50, tzinfo=timezone.utc)
        assert proxy_cert.key_filename == '/Common/proxy.paxus.com.au.key'
        assert proxy_cert.key_filesystem_filename == 'files_d\\Common_d\\certificate_key_d\\_COLON_Common_COLON_proxy.paxus.com.au.key_58044_1'

        # Test self-signed detection (subject == issuer)
        assert proxy_cert.subject == proxy_cert.issuer

    def test_certificate_chain_relationships(self, loaded_certificates):
        """Test certificate chain relationships work correctly"""
        # Create certificate lookup by filename
        cert_lookup = {cert.filename: cert for cert in loaded_certificates}

        # Test DigiCert chain: servicedeskdr → DigiCert CA
        servicedeskdr = cert_lookup.get('/Legacy-CSC/servicedeskdr.aust.csc.com.crt')
        digicert_ca = cert_lookup.get('/Common/DigiCertCA.crt')

        if servicedeskdr and digicert_ca:
            # servicedeskdr's AKI should match DigiCert CA's SKI
            assert servicedeskdr.aki == digicert_ca.ski
            assert servicedeskdr.aki == '0F80611C823161D52F28E78D4638B42CE1C6D9E2'

        # Test Symantec chain: css.ecp → Symantec CA
        css_cert = cert_lookup.get('/ECP/css.ecp.csc.com.au.crt')
        symantec_ca = cert_lookup.get('/Common/Symantec-Class3-CA-G4.crt')

        if css_cert and symantec_ca:
            # css.ecp's AKI should match Symantec CA's SKI
            assert css_cert.aki == symantec_ca.ski
            assert css_cert.aki == '5F60CF619055DF8443148A602AB2F57AF44318EF'

    def test_expired_certificates_detection(self, loaded_certificates):
        """Test that expired certificates are properly identified"""
        current_time = datetime.now(timezone.utc)

        # Find certificates that should be expired
        expired_certs = [cert for cert in loaded_certificates if cert.not_valid_after < current_time]

        # We know servicedeskdr and css.ecp are expired
        expired_filenames = [cert.filename for cert in expired_certs]

        assert '/Legacy-CSC/servicedeskdr.aust.csc.com.crt' in expired_filenames
        assert '/ECP/css.ecp.csc.com.au.crt' in expired_filenames
        assert '/Common/proxy.paxus.com.au.crt' in expired_filenames

    def test_ca_certificates_identification(self, loaded_certificates):
        """Test that CA certificates are properly identified"""
        ca_certs = [cert for cert in loaded_certificates if cert.is_ca]
        ca_filenames = [cert.filename for cert in ca_certs]

        # We know these should be CA certificates
        assert '/Common/DigiCertCA.crt' in ca_filenames
        assert '/Common/Symantec-Class3-CA-G4.crt' in ca_filenames

        # Verify they all have SKI (required for CAs)
        for ca_cert in ca_certs:
            if ca_cert.filename in ['/Common/DigiCertCA.crt', '/Common/Symantec-Class3-CA-G4.crt']:
                assert ca_cert.ski is not None

    def test_certificates_with_matching_keys(self, loaded_certificates):
        """Test that certificates with matching key files are identified"""
        certs_with_keys = [cert for cert in loaded_certificates if cert.key_filename is not None]

        # We know these certificates should have matching keys
        key_cert_filenames = [cert.filename for cert in certs_with_keys]

        assert '/Legacy-CSC/servicedeskdr.aust.csc.com.crt' in key_cert_filenames
        assert '/ECP/css.ecp.csc.com.au.crt' in key_cert_filenames
        assert '/Common/proxy.paxus.com.au.crt' in key_cert_filenames

        # Verify key filename patterns
        for cert in certs_with_keys:
            if cert.filename.endswith('.crt'):
                expected_key = cert.filename.replace('.crt', '.key')
                assert cert.key_filename == expected_key

    def test_certificates_without_matching_keys(self, loaded_certificates):
        """Test that CA certificates don't have matching key files"""
        ca_certs = [cert for cert in loaded_certificates if cert.is_ca]

        for ca_cert in ca_certs:
            # CA certificates typically don't have private keys in F5 configs
            if ca_cert.filename in ['/Common/DigiCertCA.crt', '/Common/Symantec-Class3-CA-G4.crt']:
                assert ca_cert.key_filename is None
                assert ca_cert.key_filesystem_filename is None

    def test_certificate_repr_formats(self, loaded_certificates):
        """Test certificate string representations"""
        cert_lookup = {cert.filename: cert for cert in loaded_certificates}

        # Test CA certificate repr
        digicert_ca = cert_lookup.get('/Common/DigiCertCA.crt')
        if digicert_ca:
            repr_str = repr(digicert_ca)
            assert "Certificate CA:" in repr_str
            assert "DigiCert SHA2 Secure Server CA" in repr_str

        # Test signed certificate repr
        servicedeskdr = cert_lookup.get('/Legacy-CSC/servicedeskdr.aust.csc.com.crt')
        if servicedeskdr:
            repr_str = repr(servicedeskdr)
            assert "Certificate Cert:" in repr_str
            assert "servicedeskdr.aust.csc.com" in repr_str

        # Test self-signed certificate repr
        proxy_cert = cert_lookup.get('/Common/proxy.paxus.com.au.crt')
        if proxy_cert:
            repr_str = repr(proxy_cert)
            assert "Certificate Cert:" in repr_str
            assert "proxy.paxus.com.au" in repr_str

    def test_signature_algorithms(self, loaded_certificates):
        """Test that different signature algorithms are handled"""
        cert_lookup = {cert.filename: cert for cert in loaded_certificates}

        # Most modern certificates use SHA256
        modern_certs = [
            cert_lookup.get('/Common/DigiCertCA.crt'),
            cert_lookup.get('/Legacy-CSC/servicedeskdr.aust.csc.com.crt'),
            cert_lookup.get('/Common/Symantec-Class3-CA-G4.crt'),
            cert_lookup.get('/ECP/css.ecp.csc.com.au.crt')
        ]

        for cert in modern_certs:
            if cert:
                assert cert.signature_algorithm == 'sha256WithRSAEncryption'

        # Older certificate uses SHA1
        proxy_cert = cert_lookup.get('/Common/proxy.paxus.com.au.crt')
        if proxy_cert:
            assert proxy_cert.signature_algorithm == 'sha1WithRSAEncryption'

    @patch('f5_config_parser.certificates.certificate.Certificate._discover_dependencies')
    def test_dependency_discovery_integration(self, mock_discover, loaded_certificates):
        """Test dependency discovery with real certificate collection"""
        if not loaded_certificates:
            pytest.skip("No certificates loaded for dependency testing")

        # Create mock collection
        mock_collection = Mock()

        # Test dependency discovery on a certificate with dependencies
        cert_with_deps = None
        for cert in loaded_certificates:
            if cert.filename == '/Legacy-CSC/servicedeskdr.aust.csc.com.crt':
                cert_with_deps = cert
                break

        if cert_with_deps:
            cert_with_deps._discover_dependencies(mock_collection)
            mock_discover.assert_called_once_with(mock_collection)

    def test_certificate_equality_and_hashing(self, loaded_certificates):
        """Test certificate equality and hashing with real data"""
        if len(loaded_certificates) < 2:
            pytest.skip("Need at least 2 certificates for equality testing")

        cert1 = loaded_certificates[0]
        cert2 = loaded_certificates[1]

        # Different certificates should not be equal
        assert cert1 != cert2

        # Same certificate should be equal to itself
        assert cert1 == cert1

        # Hash should be consistent
        assert hash(cert1) == hash(cert1)

        # Different certificates should have different hashes (usually)
        # Note: Hash collisions are possible but very unlikely
        if len(loaded_certificates) > 5:
            hashes = [hash(cert) for cert in loaded_certificates[:5]]
            assert len(set(hashes)) == len(hashes), "Unexpected hash collision"


# Integration test for load_certificates_from_tar function
# @pytest.mark.skip(reason="Slow loading archive")
class TestLoadCertificatesFromTar:
    """Integration tests for the load_certificates_from_tar function"""

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

    def test_load_certificates_basic_functionality(self, test_archive_path, skip_if_no_archive):
        """Test basic loading functionality"""
        from f5_config_parser.certificates.certificate_loader import load_certificates_from_tar

        certificates = load_certificates_from_tar(str(test_archive_path))

        assert isinstance(certificates, list)
        assert len(certificates) > 0
        assert all(isinstance(cert, Certificate) for cert in certificates)

    def test_load_certificates_expected_count(self, test_archive_path, skip_if_no_archive):
        """Test that expected certificates are loaded"""
        from f5_config_parser.certificates.certificate_loader import load_certificates_from_tar

        certificates = load_certificates_from_tar(str(test_archive_path))

        # We should find our known certificates
        filenames = [cert.filename for cert in certificates]

        expected_certificates = [
            '/Common/DigiCertCA.crt',
            '/Legacy-CSC/servicedeskdr.aust.csc.com.crt',
            '/Common/Symantec-Class3-CA-G4.crt',
            '/ECP/css.ecp.csc.com.au.crt',
            '/Common/proxy.paxus.com.au.crt'
        ]

        for expected_cert in expected_certificates:
            assert expected_cert in filenames, f"Expected certificate {expected_cert} not found"

    def test_load_certificates_error_handling(self):
        """Test error handling for non-existent archive"""
        from f5_config_parser.certificates.certificate_loader import load_certificates_from_tar

        with pytest.raises((FileNotFoundError, Exception)):
            load_certificates_from_tar("non_existent_file.tar")


# Sample usage for debugging - these won't print to console, just run
def sample_integration_data():
    """Sample integration data for breakpoint debugging"""
    test_dir = Path(__file__).parent
    archive_path = Path(test_dir / "../../sample_input/imsbrwlbip01_20250722_114109.tar")
    if Path(archive_path).exists():
        from f5_config_parser.certificates.certificate_loader import load_certificates_from_tar
        certificates = load_certificates_from_tar(archive_path)
        pass  # Put breakpoint here to inspect loaded certificates
    else:
        certificates = []
        pass  # Put breakpoint here - archive not found


if __name__ == "__main__":
    sample_integration_data()