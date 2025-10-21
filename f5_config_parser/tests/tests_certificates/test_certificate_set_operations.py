import pytest
import tempfile
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, timezone
import shutil
import binascii

from f5_config_parser.certificates.certificate import Certificate


class TestCertificateEqualityAndHashing:
    """Test Certificate equality and hashing with set operations"""

    @pytest.fixture
    def temp_cert_dir(self):
        """Create temporary directory for test certificates"""
        temp_dir = Path(tempfile.mkdtemp())
        yield temp_dir
        shutil.rmtree(temp_dir)

    def create_test_certificate(self, subject_cn, serial_number, temp_dir, filename):
        """Helper to create a test certificate with specific attributes"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AU"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organisation"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            serial_number
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).sign(private_key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        cert_file = temp_dir / filename
        cert_file.write_bytes(cert_pem)

        return cert, cert_pem

    def test_different_paths_different_certificates(self, temp_cert_dir):
        """Test that certificates with different paths are different (based on full_path and cert_id)"""
        # Create the same certificate content in different files
        serial_num = 12345
        cert1_data, cert1_pem = self.create_test_certificate("test.example.com", serial_num, temp_cert_dir, "cert1.crt")
        cert2_data, cert2_pem = self.create_test_certificate("test.example.com", serial_num, temp_cert_dir, "cert2.crt")

        clean_to_filesystem = {
            ('certificate', "cert1.crt"): "cert1.crt",
            ('certificate', "cert2.crt"): "cert2.crt"
        }

        cert1 = Certificate(('certificate', "cert1.crt"), "cert1.crt", temp_cert_dir, clean_to_filesystem)
        cert2 = Certificate(('certificate', "cert2.crt"), "cert2.crt", temp_cert_dir, clean_to_filesystem)

        # They should NOT be equal (different full_path and cert_id)
        assert cert1 != cert2
        assert cert2 != cert1  # Symmetric

        # Hash should be different (based on full_path and cert_id)
        assert hash(cert1) != hash(cert2)
        assert cert1.full_path != cert2.full_path

    def test_same_path_same_certificate(self, temp_cert_dir):
        """Test that certificates with same path and cert_id are equal"""
        cert1_data, cert1_pem = self.create_test_certificate("test.example.com", 12345, temp_cert_dir, "cert1.crt")

        clean_to_filesystem = {('certificate', "cert1.crt"): "cert1.crt"}

        # Create two Certificate objects with same parameters
        cert1 = Certificate(('certificate', "cert1.crt"), "cert1.crt", temp_cert_dir, clean_to_filesystem)
        cert2 = Certificate(('certificate', "cert1.crt"), "cert1.crt", temp_cert_dir, clean_to_filesystem)

        # They should be equal (same full_path and cert_id)
        assert cert1 == cert2
        assert cert2 == cert1  # Symmetric

        # Hash should be the same
        assert hash(cert1) == hash(cert2)

    def test_certificate_string_comparison(self, temp_cert_dir):
        """Test certificate comparison with strings (compares full_path only)"""
        cert_data, cert_pem = self.create_test_certificate("test.example.com", 12345, temp_cert_dir, "cert.crt")

        clean_to_filesystem = {('certificate', "cert.crt"): "cert.crt"}
        cert = Certificate(('certificate', "cert.crt"), "cert.crt", temp_cert_dir, clean_to_filesystem)

        # Should be equal to its full_path string
        assert cert == cert.full_path
        assert cert.full_path == cert  # Should work both ways

        # Should not be equal to other strings
        assert cert != "other_path"
        assert cert != "cert.crt"  # This is not the full_path

    def test_certificate_not_equal_to_other_types(self, temp_cert_dir):
        """Test that certificates are not equal to other object types"""
        cert_data, cert_pem = self.create_test_certificate("test.example.com", 12345, temp_cert_dir, "cert.crt")

        clean_to_filesystem = {('certificate', "cert.crt"): "cert.crt"}
        cert = Certificate(('certificate', "cert.crt"), "cert.crt", temp_cert_dir, clean_to_filesystem)

        # Should not be equal to other types (except strings which compare to full_path)
        assert cert != 12345
        assert cert != ["list"]
        assert cert != {"dict": "value"}
        assert cert != None

    def test_certificate_set_operations_with_different_paths(self, temp_cert_dir):
        """Test set operations with certificates having different paths"""
        # Create multiple certificates with different paths (all will be different)
        serial_num = 12345
        cert1_data, cert1_pem = self.create_test_certificate("test.example.com", serial_num, temp_cert_dir, "cert1.crt")
        cert2_data, cert2_pem = self.create_test_certificate("test.example.com", serial_num, temp_cert_dir, "cert2.crt")
        cert3_data, cert3_pem = self.create_test_certificate("test.example.com", serial_num, temp_cert_dir, "cert3.crt")

        clean_to_filesystem = {
            ('certificate', "cert1.crt"): "cert1.crt",
            ('certificate', "cert2.crt"): "cert2.crt",
            ('certificate', "cert3.crt"): "cert3.crt"
        }

        cert1 = Certificate(('certificate', "cert1.crt"), "cert1.crt", temp_cert_dir, clean_to_filesystem)
        cert2 = Certificate(('certificate', "cert2.crt"), "cert2.crt", temp_cert_dir, clean_to_filesystem)
        cert3 = Certificate(('certificate', "cert3.crt"), "cert3.crt", temp_cert_dir, clean_to_filesystem)

        # All should be different (different full_path and cert_id)
        assert cert1 != cert2 != cert3

        # All should have different hashes (different full_path and cert_id)
        assert hash(cert1) != hash(cert2)
        assert hash(cert2) != hash(cert3)
        assert hash(cert1) != hash(cert3)

        # Create a set - should contain ALL THREE certificates (different paths/cert_ids)
        cert_set = {cert1, cert2, cert3}
        assert len(cert_set) == 3  # All three should be in set due to different hashes

        # All should be in the set
        assert cert1 in cert_set
        assert cert2 in cert_set
        assert cert3 in cert_set

    def test_certificate_set_operations_with_unique_certificates(self, temp_cert_dir):
        """Test set operations with unique certificates"""
        # Create certificates with different serial numbers and paths
        cert1_data, cert1_pem = self.create_test_certificate("test1.example.com", 11111, temp_cert_dir, "cert1.crt")
        cert2_data, cert2_pem = self.create_test_certificate("test2.example.com", 22222, temp_cert_dir, "cert2.crt")
        cert3_data, cert3_pem = self.create_test_certificate("test3.example.com", 33333, temp_cert_dir, "cert3.crt")

        clean_to_filesystem = {
            ('certificate', "cert1.crt"): "cert1.crt",
            ('certificate', "cert2.crt"): "cert2.crt",
            ('certificate', "cert3.crt"): "cert3.crt"
        }

        cert1 = Certificate(('certificate', "cert1.crt"), "cert1.crt", temp_cert_dir, clean_to_filesystem)
        cert2 = Certificate(('certificate', "cert2.crt"), "cert2.crt", temp_cert_dir, clean_to_filesystem)
        cert3 = Certificate(('certificate', "cert3.crt"), "cert3.crt", temp_cert_dir, clean_to_filesystem)

        # All should be different
        assert cert1 != cert2
        assert cert2 != cert3
        assert cert1 != cert3

        # Create a set
        cert_set = {cert1, cert2, cert3}
        assert len(cert_set) == 3

        # Test set membership
        assert cert1 in cert_set
        assert cert2 in cert_set
        assert cert3 in cert_set

        # Test set union
        set1 = {cert1, cert2}
        set2 = {cert2, cert3}
        union_set = set1 | set2
        assert len(union_set) == 3  # cert1, cert2, cert3
        assert cert1 in union_set
        assert cert2 in union_set
        assert cert3 in union_set

        # Test set intersection
        intersection_set = set1 & set2
        assert len(intersection_set) == 1  # Only cert2
        assert cert2 in intersection_set
        assert cert1 not in intersection_set
        assert cert3 not in intersection_set

        # Test set difference
        diff_set = set1 - set2
        assert len(diff_set) == 1  # Only cert1
        assert cert1 in diff_set
        assert cert2 not in diff_set
        assert cert3 not in diff_set

    def test_certificate_deduplication_in_sets(self, temp_cert_dir):
        """Test that duplicate Certificate objects are correctly deduplicated in sets"""
        cert_data, cert_pem = self.create_test_certificate("test.example.com", 12345, temp_cert_dir, "cert.crt")

        clean_to_filesystem = {('certificate', "cert.crt"): "cert.crt"}

        # Create multiple Certificate objects with identical parameters
        cert1 = Certificate(('certificate', "cert.crt"), "cert.crt", temp_cert_dir, clean_to_filesystem)
        cert2 = Certificate(('certificate', "cert.crt"), "cert.crt", temp_cert_dir, clean_to_filesystem)
        cert3 = Certificate(('certificate', "cert.crt"), "cert.crt", temp_cert_dir, clean_to_filesystem)

        # All should be equal
        assert cert1 == cert2 == cert3

        # When added to a set, should be deduplicated (same full_path and cert_id)
        cert_set = {cert1, cert2, cert3}
        assert len(cert_set) == 1  # Should only contain one unique certificate

        # The one in the set should be equal to all three
        cert_in_set = list(cert_set)[0]
        assert cert_in_set == cert1
        assert cert_in_set == cert2
        assert cert_in_set == cert3

    def test_certificate_set_operations_with_overlapping_collections(self, temp_cert_dir):
        """Test set operations with overlapping collections of certificates"""
        # Create 5 certificates
        cert_data1, cert_pem1 = self.create_test_certificate("test1.example.com", 11111, temp_cert_dir, "cert1.crt")
        cert_data2, cert_pem2 = self.create_test_certificate("test2.example.com", 22222, temp_cert_dir, "cert2.crt")
        cert_data_shared, cert_pem_shared = self.create_test_certificate("shared.example.com", 99999, temp_cert_dir,
                                                                         "shared.crt")
        cert_data3, cert_pem3 = self.create_test_certificate("test3.example.com", 33333, temp_cert_dir, "cert3.crt")
        cert_data4, cert_pem4 = self.create_test_certificate("test4.example.com", 44444, temp_cert_dir, "cert4.crt")

        clean_to_filesystem = {
            ('certificate', "cert1.crt"): "cert1.crt",
            ('certificate', "cert2.crt"): "cert2.crt",
            ('certificate', "shared.crt"): "shared.crt",
            ('certificate', "cert3.crt"): "cert3.crt",
            ('certificate', "cert4.crt"): "cert4.crt"
        }

        cert1 = Certificate(('certificate', "cert1.crt"), "cert1.crt", temp_cert_dir, clean_to_filesystem)
        cert2 = Certificate(('certificate', "cert2.crt"), "cert2.crt", temp_cert_dir, clean_to_filesystem)
        shared = Certificate(('certificate', "shared.crt"), "shared.crt", temp_cert_dir, clean_to_filesystem)
        cert3 = Certificate(('certificate', "cert3.crt"), "cert3.crt", temp_cert_dir, clean_to_filesystem)
        cert4 = Certificate(('certificate', "cert4.crt"), "cert4.crt", temp_cert_dir, clean_to_filesystem)

        # Create two collections with overlap
        collection1 = {cert1, cert2, shared}
        collection2 = {shared, cert3, cert4}

        # Test union
        union_set = collection1 | collection2
        assert len(union_set) == 5  # All unique certificates
        assert cert1 in union_set
        assert cert2 in union_set
        assert shared in union_set
        assert cert3 in union_set
        assert cert4 in union_set

        # Test intersection
        intersection_set = collection1 & collection2
        assert len(intersection_set) == 1  # Only shared
        assert shared in intersection_set
        assert cert1 not in intersection_set
        assert cert2 not in intersection_set
        assert cert3 not in intersection_set
        assert cert4 not in intersection_set

        # Test difference
        diff_set = collection1 - collection2
        assert len(diff_set) == 2  # cert1 and cert2 only
        assert cert1 in diff_set
        assert cert2 in diff_set
        assert shared not in diff_set  # shared is removed

        # Similarly, collection2 - collection1
        diff_set2 = collection2 - collection1
        assert len(diff_set2) == 2  # cert3 and cert4 only
        assert cert3 in diff_set2
        assert cert4 in diff_set2
        assert shared not in diff_set2  # shared is removed

        # Symmetric difference should contain certificates not in both
        sym_diff_set = collection1 ^ collection2
        assert len(sym_diff_set) == 4  # cert1, cert2, cert3, cert4 (not shared)
        assert cert1 in sym_diff_set
        assert cert2 in sym_diff_set
        assert cert3 in sym_diff_set
        assert cert4 in sym_diff_set
        assert shared not in sym_diff_set  # shared is in both, so excluded

    def test_certificate_hash_consistency(self, temp_cert_dir):
        """Test that certificate hashes are consistent across multiple calls"""
        cert_data, cert_pem = self.create_test_certificate("test.example.com", 12345, temp_cert_dir, "cert.crt")

        clean_to_filesystem = {('certificate', "cert.crt"): "cert.crt"}
        cert = Certificate(('certificate', "cert.crt"), "cert.crt", temp_cert_dir, clean_to_filesystem)

        # Hash should be consistent across multiple calls
        hash1 = hash(cert)
        hash2 = hash(cert)
        hash3 = hash(cert)

        assert hash1 == hash2 == hash3

    def test_certificate_equality_reflexivity(self, temp_cert_dir):
        """Test that certificate equality is reflexive (a == a)"""
        cert_data, cert_pem = self.create_test_certificate("test.example.com", 12345, temp_cert_dir, "cert.crt")

        clean_to_filesystem = {('certificate', "cert.crt"): "cert.crt"}
        cert = Certificate(('certificate', "cert.crt"), "cert.crt", temp_cert_dir, clean_to_filesystem)

        # Should be equal to itself
        assert cert == cert
        assert not (cert != cert)

    def test_certificate_equality_transitivity(self, temp_cert_dir):
        """Test that certificate equality is transitive (if a == b and b == c, then a == c)"""
        cert_data, cert_pem = self.create_test_certificate("test.example.com", 12345, temp_cert_dir, "cert.crt")

        clean_to_filesystem = {('certificate', "cert.crt"): "cert.crt"}

        # Create three Certificate objects with identical parameters
        cert1 = Certificate(('certificate', "cert.crt"), "cert.crt", temp_cert_dir, clean_to_filesystem)
        cert2 = Certificate(('certificate', "cert.crt"), "cert.crt", temp_cert_dir, clean_to_filesystem)
        cert3 = Certificate(('certificate', "cert.crt"), "cert.crt", temp_cert_dir, clean_to_filesystem)

        # Test transitivity
        assert cert1 == cert2
        assert cert2 == cert3
        assert cert1 == cert3  # Transitivity

    def test_string_filtering_operations(self, temp_cert_dir):
        """Test filtering operations using string comparison"""
        # Create subdirectory for cert3
        (temp_cert_dir / "subdir").mkdir(exist_ok=True)

        # Create certificates with different paths
        cert1_data, cert1_pem = self.create_test_certificate("test1.example.com", 11111, temp_cert_dir, "cert1.crt")
        cert2_data, cert2_pem = self.create_test_certificate("test2.example.com", 22222, temp_cert_dir, "cert2.crt")
        cert3_data, cert3_pem = self.create_test_certificate("test3.example.com", 33333, temp_cert_dir,
                                                             "subdir/cert3.crt")

        clean_to_filesystem = {
            ('certificate', "cert1.crt"): "cert1.crt",
            ('certificate', "cert2.crt"): "cert2.crt",
            ('certificate', "subdir/cert3.crt"): "subdir/cert3.crt"
        }

        cert1 = Certificate(('certificate', "cert1.crt"), "cert1.crt", temp_cert_dir, clean_to_filesystem)
        cert2 = Certificate(('certificate', "cert2.crt"), "cert2.crt", temp_cert_dir, clean_to_filesystem)
        cert3 = Certificate(('certificate', "subdir/cert3.crt"), "subdir/cert3.crt", temp_cert_dir, clean_to_filesystem)

        certificates = [cert1, cert2, cert3]

        # Test filtering by full_path using string comparison
        cert1_path = str(cert1.full_path)
        filtered = [cert for cert in certificates if cert == cert1_path]
        assert len(filtered) == 1
        assert filtered[0] == cert1

        # Test filtering by partial path (should not match as it compares full_path)
        filtered_partial = [cert for cert in certificates if cert == "cert1.crt"]
        assert len(filtered_partial) == 0  # "cert1.crt" != full_path

        # Test set membership with string - strings are not directly in certificate sets
        cert_set = {cert1, cert2, cert3}
        assert cert1_path not in cert_set  # String is not in set of Certificate objects

        # But we can check if any certificate matches the string
        matching_certs = [cert for cert in cert_set if cert == cert1_path]
        assert len(matching_certs) == 1
        assert matching_certs[0] == cert1

    def test_large_certificate_set_performance(self, temp_cert_dir):
        """Test performance with larger sets of certificates"""
        certificates = []
        clean_to_filesystem = {}

        # Create 50 certificates with unique paths
        for i in range(50):
            serial_num = i + 1  # Each certificate gets unique serial
            filename = f"cert_{i}.crt"
            cert_data, cert_pem = self.create_test_certificate(f"test{serial_num}.example.com", serial_num,
                                                               temp_cert_dir, filename)
            clean_to_filesystem[('certificate', filename)] = filename

            cert = Certificate(('certificate', filename), filename, temp_cert_dir, clean_to_filesystem)
            certificates.append(cert)

        # Convert to set - should contain ALL certificates (unique paths and cert_ids)
        cert_set = set(certificates)

        # Should have 50 certificates (all have unique paths and cert_ids)
        assert len(cert_set) == 50

        # Test set operations
        half1 = set(certificates[:25])
        half2 = set(certificates[25:])

        union = half1 | half2
        assert len(union) == 50  # All certificates (unique paths)

        # Intersection should be empty (no overlapping certificates)
        intersection = half1 & half2
        assert len(intersection) == 0  # No shared certificates between halves


# Sample usage for debugging - these won't print to console, just run
def sample_equality_test_data():
    """Sample equality test data for breakpoint debugging"""
    import tempfile
    temp_dir = Path(tempfile.mkdtemp())

    try:
        test_instance = TestCertificateEqualityAndHashing()

        # Create some test certificates
        cert1_data, cert1_pem = test_instance.create_test_certificate("test1.example.com", 11111, temp_dir, "cert1.crt")
        cert2_data, cert2_pem = test_instance.create_test_certificate("test1.example.com", 11111, temp_dir,
                                                                      "cert2.crt")  # Same content, different path
        cert3_data, cert3_pem = test_instance.create_test_certificate("test3.example.com", 33333, temp_dir,
                                                                      "cert3.crt")  # Different content

        clean_to_filesystem = {
            ('certificate', "cert1.crt"): "cert1.crt",
            ('certificate', "cert2.crt"): "cert2.crt",
            ('certificate', "cert3.crt"): "cert3.crt"
        }

        cert1 = Certificate(('certificate', "cert1.crt"), "cert1.crt", temp_dir, clean_to_filesystem)
        cert2 = Certificate(('certificate', "cert2.crt"), "cert2.crt", temp_dir, clean_to_filesystem)
        cert3 = Certificate(('certificate', "cert3.crt"), "cert3.crt", temp_dir, clean_to_filesystem)

        # Create collections for testing
        collection1 = {cert1, cert2}  # Should contain 2 certificates (different paths)
        collection2 = {cert2, cert3}  # Should contain 2 certificates

        pass  # Put breakpoint here to inspect equality and set operations

    finally:
        shutil.rmtree(temp_dir)


if __name__ == "__main__":
    sample_equality_test_data()