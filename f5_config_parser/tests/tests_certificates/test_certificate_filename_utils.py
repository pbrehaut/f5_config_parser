"""Unit tests for f5_certificates.utils module"""

import pytest
from pathlib import Path
import tempfile
import tarfile
import shutil
from f5_config_parser.certificates.certificate_loader import parse_f5_filename, build_filename_mappings


class TestParseF5Filename:
    """Test cases for parse_f5_filename function"""

    def test_parse_standard_certificate_filename(self):
        """Test parsing a standard certificate filename"""
        filesystem_filename = "files_d/Common_d/certificate_d/_COLON_Common_COLON_mycert.crt_93973_1"
        expected = ('certificate', "/Common/mycert.crt")
        result = parse_f5_filename(filesystem_filename)
        assert result == expected

    def test_parse_standard_key_filename(self):
        """Test parsing a standard key filename"""
        filesystem_filename = "files_d/Common_d/certificate_key_d/_COLON_Common_COLON_mykey.key_12345_2"
        expected = ('key', "/Common/mykey.key")
        result = parse_f5_filename(filesystem_filename)
        assert result == expected

    def test_parse_different_partition(self):
        """Test parsing filename from different partition"""
        filesystem_filename = "files_d/MyPartition_d/certificate_d/_COLON_MyPartition_COLON_cert.crt_55555_3"
        expected = ('certificate', "/MyPartition/cert.crt")
        result = parse_f5_filename(filesystem_filename)
        assert result == expected

    def test_parse_complex_certificate_name(self):
        """Test parsing certificate with complex name including hyphens and dots"""
        filesystem_filename = "files_d/Common_d/certificate_d/_COLON_Common_COLON_my-complex.cert.name.crt_11111_1"
        expected = ('certificate', "/Common/my-complex.cert.name.crt")
        result = parse_f5_filename(filesystem_filename)
        assert result == expected

    def test_parse_windows_path_separators(self):
        """Test parsing with Windows path separators"""
        filesystem_filename = r"files_d\Common_d\certificate_d\_COLON_Common_COLON_mycert.crt_93973_1"
        expected = ('certificate', "/Common/mycert.crt")
        result = parse_f5_filename(filesystem_filename)
        assert result == expected

    def test_parse_multiple_colons_in_name(self):
        """Test parsing filename that originally had multiple colons"""
        filesystem_filename = "files_d/Common_d/certificate_d/_COLON_Common_COLON_my_COLON_cert_COLON_name.crt_77777_4"
        expected = ('certificate', "/Common/my/cert/name.crt")
        result = parse_f5_filename(filesystem_filename)
        assert result == expected

    def test_invalid_filename_no_version_suffix(self):
        """Test error handling for filename without version suffix"""
        filesystem_filename = "files_d/Common_d/certificate_d/:Common:mycert.crt"
        with pytest.raises(ValueError, match="Cannot parse F5 filename"):
            parse_f5_filename(filesystem_filename)

    def test_invalid_filename_wrong_version_pattern(self):
        """Test error handling for filename with wrong version pattern"""
        filesystem_filename = "files_d/Common_d/certificate_d/:Common:mycert.crt_abc_def"
        with pytest.raises(ValueError, match="Cannot parse F5 filename"):
            parse_f5_filename(filesystem_filename)

    def test_invalid_filename_no_f5_path(self):
        """Test error handling for filename without F5 path (no colons)"""
        filesystem_filename = "some_random_file_12345_1"
        with pytest.raises(ValueError, match=f"No recognised file type directory found in: {filesystem_filename}"):
            parse_f5_filename(filesystem_filename)

    def test_invalid_filename_empty_string(self):
        """Test error handling for empty filename"""
        with pytest.raises(ValueError, match="Cannot parse F5 filename"):
            parse_f5_filename("")

    def test_edge_case_single_character_names(self):
        """Test parsing with single character certificate name"""
        filesystem_filename = "files_d/Common_d/certificate_d/_COLON_Common_COLON_x.crt_99999_9"
        expected = ('certificate', "/Common/x.crt")
        result = parse_f5_filename(filesystem_filename)
        assert result == expected


class TestBuildFilenameMappings:
    """Test cases for build_filename_mappings function"""

    def setup_method(self):
        """Set up temporary directory with test files for each test"""
        self.temp_dir = Path(tempfile.mkdtemp())

        # Create test file structure
        test_files = [
            "files_d/Common_d/certificate_d/_COLON_Common_COLON_cert1.crt_12345_1",
            "files_d/Common_d/certificate_d/_COLON_Common_COLON_cert2.crt_67890_2",
            "files_d/Common_d/certificate_key_d/_COLON_Common_COLON_cert1.key_12345_1",
            "files_d/MyPartition_d/certificate_d/_COLON_MyPartition_COLON_cert3.crt_11111_1",
            "some_random_file.txt",  # This should be skipped
            "another_unparseable_file_without_proper_format"  # This should be skipped
        ]

        for file_path in test_files:
            full_path = self.temp_dir / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text("dummy content")

    def teardown_method(self):
        """Clean up temporary directory after each test"""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    def test_build_mappings_basic_functionality(self):
        """Test basic functionality of building filename mappings"""
        filesystem_to_clean, clean_to_filesystem = build_filename_mappings(self.temp_dir)

        # Should have mappings for parseable files only
        expected_clean_files = {
            ('certificate', "/Common/cert1.crt"),
            ('certificate', "/Common/cert2.crt"),
            ('key', "/Common/cert1.key"),
            ('certificate', "/MyPartition/cert3.crt")
        }

        assert set(clean_to_filesystem.keys()) == expected_clean_files
        assert len(clean_to_filesystem) == 4

    def test_build_mappings_certificate_and_key_pairing(self):
        """Test that certificates and keys are properly paired with tuple keys"""
        filesystem_to_clean, clean_to_filesystem = build_filename_mappings(self.temp_dir)

        # Check certificate mapping
        cert1_tuple = ('certificate', "/Common/cert1.crt")
        assert cert1_tuple in clean_to_filesystem
        assert "cert1.crt" in clean_to_filesystem[cert1_tuple]

        # Check key mapping - key uses the certificate filename as the clean name
        key1_tuple = ('key', "/Common/cert1.key")
        assert key1_tuple in clean_to_filesystem
        assert "cert1.key" in clean_to_filesystem[key1_tuple]

    def test_build_mappings_skips_unparseable_files(self):
        """Test that unparseable files are skipped without causing errors"""
        filesystem_to_clean, clean_to_filesystem = build_filename_mappings(self.temp_dir)

        # Unparseable files should not be in mappings
        all_filesystem_files = set(clean_to_filesystem.values())

        assert "some_random_file.txt" not in all_filesystem_files
        assert "another_unparseable_file_without_proper_format" not in all_filesystem_files

    def test_build_mappings_empty_directory(self):
        """Test behaviour with empty directory"""
        empty_dir = Path(tempfile.mkdtemp())
        try:
            filesystem_to_clean, clean_to_filesystem = build_filename_mappings(empty_dir)
            assert len(clean_to_filesystem) == 0
        finally:
            shutil.rmtree(empty_dir)

    def test_build_mappings_directories_only(self):
        """Test behaviour with directory containing only subdirectories, no files"""
        dirs_only = Path(tempfile.mkdtemp())
        try:
            # Create some directories but no files
            (dirs_only / "subdir1" / "subdir2").mkdir(parents=True)
            (dirs_only / "another_dir").mkdir()

            filesystem_to_clean, clean_to_filesystem = build_filename_mappings(dirs_only)
            assert len(clean_to_filesystem) == 0
        finally:
            shutil.rmtree(dirs_only)

    def test_build_mappings_tuple_key_structure(self):
        """Test that all keys are tuples with correct structure"""
        filesystem_to_clean, clean_to_filesystem = build_filename_mappings(self.temp_dir)

        for key, value in clean_to_filesystem.items():
            # All keys should be tuples
            assert isinstance(key, tuple)
            # All tuples should have exactly 2 elements
            assert len(key) == 2
            # First element should be 'certificate' or 'key'
            assert key[0] in ('certificate', 'key')
            # Second element should be a string (the clean filename)
            assert isinstance(key[1], str)
            # Value should be a string (the filesystem filename)
            assert isinstance(value, str)


# Test data for parametrised tests
VALID_FILENAME_CASES = [
    ("files_d/Common_d/certificate_d/_COLON_Common_COLON_test.crt_12345_1", ('certificate', "/Common/test.crt")),
    ("files_d/Prod_d/certificate_key_d/_COLON_Prod_COLON_prod-key.key_99999_5", ('key', "/Prod/prod-key.key")),
    ("files_d/Test_d/certificate_d/_COLON_Test_COLON_my_COLON_complex_COLON_name.crt_55555_3",
     ('certificate', "/Test/my/complex/name.crt")),
]

INVALID_FILENAME_CASES = [
    "no_version_suffix",
    "wrong_version_12345_abc",
    "no_f5_path_12345_1",
    "",
    "files_d/Common_d/no_colon_part_12345_1"
]


class TestParseF5FilenameParametrized:
    """Parametrised tests for parse_f5_filename function"""

    @pytest.mark.parametrize("filesystem_filename,expected", VALID_FILENAME_CASES)
    def test_valid_filenames(self, filesystem_filename, expected):
        """Test various valid filename patterns"""
        result = parse_f5_filename(filesystem_filename)
        assert result == expected

    @pytest.mark.parametrize("invalid_filename", INVALID_FILENAME_CASES)
    def test_invalid_filenames(self, invalid_filename):
        """Test various invalid filename patterns"""
        with pytest.raises(ValueError):
            parse_f5_filename(invalid_filename)