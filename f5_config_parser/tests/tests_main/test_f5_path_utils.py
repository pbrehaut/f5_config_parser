"""Test cases for F5 archive path utilities"""
import pytest
from f5_config_parser.f5_path_utils import rename_f5_archive_path


class TestRenameF5ArchivePath:
    """Test cases for rename_f5_archive_path function"""

    # Windows-style paths with _COLON_ format
    def test_windows_cert_path_same_partition(self):
        """Test Windows-style certificate path with same partition"""
        original = r'var\tmp\filestore_temp\files_d\CBU-AdminNet_d\certificate_d\_COLON_CBU-AdminNet_COLON_cloudcompute-proxy.au3.csc.com.crt_58168_1'
        source = '/CBU-AdminNet/cloudcompute-proxy.au3.csc.com.crt'
        result = rename_f5_archive_path(
            original,
            source,
            'CBU-AdminNet',
            'cloudcompute-proxy.au3.csc.com_2015_09',
            dir_separator='\\',
            colon_format='_COLON_'
        )
        expected = r'var\tmp\filestore_temp\files_d\CBU-AdminNet_d\certificate_d\_COLON_CBU-AdminNet_COLON_cloudcompute-proxy.au3.csc.com_2015_09_58168_1'
        assert result == expected

    def test_windows_cert_path_different_partition(self):
        """Test Windows-style certificate path with different partition"""
        original = r'var\tmp\filestore_temp\files_d\CBU-AdminNet_d\certificate_d\_COLON_CBU-AdminNet_COLON_cloudcompute-proxy.au3.csc.com.crt_58168_1'
        source = '/CBU-AdminNet/cloudcompute-proxy.au3.csc.com.crt'
        result = rename_f5_archive_path(
            original,
            source,
            'Production',
            'cloudcompute-proxy.au3.csc.com_2015_09',
            dir_separator='\\',
            colon_format='_COLON_'
        )
        expected = r'var\tmp\filestore_temp\files_d\Production_d\certificate_d\_COLON_Production_COLON_cloudcompute-proxy.au3.csc.com_2015_09_58168_1'
        assert result == expected

    def test_windows_key_path_same_partition(self):
        """Test Windows-style key path with same partition"""
        original = r'var\tmp\filestore_temp\files_d\CBU-AdminNet_d\certificate_key_d\_COLON_CBU-AdminNet_COLON_cloudcompute-proxy.au3.csc.com.key_58132_1'
        source = '/CBU-AdminNet/cloudcompute-proxy.au3.csc.com.key'
        result = rename_f5_archive_path(
            original,
            source,
            'CBU-AdminNet',
            'cloudcompute-proxy.au3.csc.com_2015_09',
            dir_separator='\\',
            colon_format='_COLON_'
        )
        expected = r'var\tmp\filestore_temp\files_d\CBU-AdminNet_d\certificate_key_d\_COLON_CBU-AdminNet_COLON_cloudcompute-proxy.au3.csc.com_2015_09_58132_1'
        assert result == expected

    def test_windows_key_path_different_partition(self):
        """Test Windows-style key path with different partition"""
        original = r'var\tmp\filestore_temp\files_d\CBU-AdminNet_d\certificate_key_d\_COLON_CBU-AdminNet_COLON_cloudcompute-proxy.au3.csc.com.key_58132_1'
        source = '/CBU-AdminNet/cloudcompute-proxy.au3.csc.com.key'
        result = rename_f5_archive_path(
            original,
            source,
            'Development',
            'cloudcompute-proxy.au3.csc.com_2015_09',
            dir_separator='\\',
            colon_format='_COLON_'
        )
        expected = r'var\tmp\filestore_temp\files_d\Development_d\certificate_key_d\_COLON_Development_COLON_cloudcompute-proxy.au3.csc.com_2015_09_58132_1'
        assert result == expected

    # Unix-style paths with : format
    def test_unix_cert_path_same_partition(self):
        """Test Unix-style certificate path with same partition"""
        original = '/config/filestore/files_d/CBU-AdminNet_d/certificate_d/:CBU-AdminNet:cloudstore.au3.apacvbk.cbu.csc.com.crt_58184_1'
        source = '/CBU-AdminNet/cloudstore.au3.apacvbk.cbu.csc.com.crt'
        result = rename_f5_archive_path(
            original,
            source,
            'CBU-AdminNet',
            'cloudstore.au3.apacvbk.cbu.csc.com_2015_09',
            dir_separator='/',
            colon_format=':'
        )
        expected = '/config/filestore/files_d/CBU-AdminNet_d/certificate_d/:CBU-AdminNet:cloudstore.au3.apacvbk.cbu.csc.com_2015_09_58184_1'
        assert result == expected

    def test_unix_cert_path_different_partition(self):
        """Test Unix-style certificate path with different partition"""
        original = '/config/filestore/files_d/CBU-AdminNet_d/certificate_d/:CBU-AdminNet:cloudstore.au3.apacvbk.cbu.csc.com.crt_58184_1'
        source = '/CBU-AdminNet/cloudstore.au3.apacvbk.cbu.csc.com.crt'
        result = rename_f5_archive_path(
            original,
            source,
            'Production',
            'cloudstore.au3.apacvbk.cbu.csc.com_2015_09',
            dir_separator='/',
            colon_format=':'
        )
        expected = '/config/filestore/files_d/Production_d/certificate_d/:Production:cloudstore.au3.apacvbk.cbu.csc.com_2015_09_58184_1'
        assert result == expected

    def test_unix_key_path_same_partition(self):
        """Test Unix-style key path with same partition"""
        original = '/config/filestore/files_d/Common_d/certificate_key_d/:Common:uat.helphub.net.au.key_58060_1'
        source = '/Common/uat.helphub.net.au.key'
        result = rename_f5_archive_path(
            original,
            source,
            'Common',
            'uat.helphub.net.au_2025_08',
            dir_separator='/',
            colon_format=':'
        )
        expected = '/config/filestore/files_d/Common_d/certificate_key_d/:Common:uat.helphub.net.au_2025_08_58060_1'
        assert result == expected

    def test_unix_key_path_different_partition(self):
        """Test Unix-style key path with different partition"""
        original = '/config/filestore/files_d/Common_d/certificate_key_d/:Common:uat.helphub.net.au.key_58060_1'
        source = '/Common/uat.helphub.net.au.key'
        result = rename_f5_archive_path(
            original,
            source,
            'Staging',
            'uat.helphub.net.au_2025_08',
            dir_separator='/',
            colon_format=':'
        )
        expected = '/config/filestore/files_d/Staging_d/certificate_key_d/:Staging:uat.helphub.net.au_2025_08_58060_1'
        assert result == expected

    # Edge cases
    def test_none_input(self):
        """Test with None input"""
        result = rename_f5_archive_path(
            None,
            '/Common/cert.crt',
            'NewPartition',
            'newcert_2025_09',
            dir_separator='\\',
            colon_format='_COLON_'
        )
        assert result is None

    def test_empty_string_input(self):
        """Test with empty string input"""
        result = rename_f5_archive_path(
            '',
            '/Common/cert.crt',
            'NewPartition',
            'newcert_2025_09',
            dir_separator='\\',
            colon_format='_COLON_'
        )
        assert result is None

    def test_complex_partition_name(self):
        """Test with complex partition name containing special characters"""
        original = r'var\tmp\files_d\CBU-AdminNet_d\certificate_d\_COLON_CBU-AdminNet_COLON_test.crt_123_1'
        source = '/CBU-AdminNet/test.crt'
        result = rename_f5_archive_path(
            original,
            source,
            'NewPart-123_Test',
            'newtest_2025_09',
            dir_separator='\\',
            colon_format='_COLON_'
        )
        expected = r'var\tmp\files_d\NewPart-123_Test_d\certificate_d\_COLON_NewPart-123_Test_COLON_newtest_2025_09_123_1'
        assert result == expected

    def test_long_certificate_name(self):
        """Test with very long certificate name"""
        original = r'var\tmp\files_d\Production_d\certificate_d\_COLON_Production_COLON_very.long.subdomain.example.company.com.au.crt_99999_1'
        source = '/Production/very.long.subdomain.example.company.com.au.crt'
        result = rename_f5_archive_path(
            original,
            source,
            'Production',
            'very.long.subdomain.example.company.com.au_2025_12',
            dir_separator='\\',
            colon_format='_COLON_'
        )
        expected = r'var\tmp\files_d\Production_d\certificate_d\_COLON_Production_COLON_very.long.subdomain.example.company.com.au_2025_12_99999_1'
        assert result == expected

    def test_partition_change_common_to_custom(self):
        """Test changing partition from Common to custom partition"""
        original = r'var\tmp\files_d\Common_d\certificate_d\_COLON_Common_COLON_mycert.crt_12345_1'
        source = '/Common/mycert.crt'
        result = rename_f5_archive_path(
            original,
            source,
            'MyCustomPartition',
            'mycert_2025_10',
            dir_separator='\\',
            colon_format='_COLON_'
        )
        expected = r'var\tmp\files_d\MyCustomPartition_d\certificate_d\_COLON_MyCustomPartition_COLON_mycert_2025_10_12345_1'
        assert result == expected


if __name__ == '__main__':
    pytest.main([__file__, '-v'])