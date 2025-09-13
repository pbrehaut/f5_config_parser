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

    def test_identical_certificates_are_equal_but_different_hashes(self, temp_cert_dir):
        """Test that identical certificates are equal but have different hashes (different paths)"""
        # Create the same certificate twice (same serial number and issuer)
        serial_num = 12345
        cert1_data, cert1_pem = self.create_test_certificate("test.example.com", serial_num, temp_cert_dir, "cert1.crt")
        cert2_data, cert2_pem = self.create_test_certificate("test.example.com", serial_num, temp_cert_dir, "cert2.crt")

        # Note: These will have different private keys but same serial/issuer
        clean_to_filesystem = {
            "cert1.crt": "cert1.crt",
            "cert2.crt": "cert2.crt"
        }

        cert1 = Certificate("cert1.crt", "cert1.crt", temp_cert_dir, clean_to_filesystem)
        cert2 = Certificate("cert2.crt", "cert2.crt", temp_cert_dir, clean_to_filesystem)

        # They should be equal (same serial number and issuer)
        assert cert1 == cert2
        assert cert2 == cert1  # Symmetric

        # Hash should be DIFFERENT (based on full_path, not certificate content)
        assert hash(cert1) != hash(cert2)
        assert cert1.full_path != cert2.full_path

    def test_different_serial_numbers_not_equal(self, temp_cert_dir):
        """Test that certificates with different serial numbers are not equal"""
        cert1_data, cert1_pem = self.create_test_certificate("test.example.com", 12345, temp_cert_dir, "cert1.crt")
        cert2_data, cert2_pem = self.create_test_certificate("test.example.com", 67890, temp_cert_dir, "cert2.crt")

        clean_to_filesystem = {
            "cert1.crt": "cert1.crt",
            "cert2.crt": "cert2.crt"
        }

        cert1 = Certificate("cert1.crt", "cert1.crt", temp_cert_dir, clean_to_filesystem)
        cert2 = Certificate("cert2.crt", "cert2.crt", temp_cert_dir, clean_to_filesystem)

        # They should not be equal (different serial numbers)
        assert cert1 != cert2
        assert cert2 != cert1  # Symmetric

        # Hash should likely be different (not guaranteed but very likely)
        assert hash(cert1) != hash(cert2)

    def test_different_issuers_not_equal(self, temp_cert_dir):
        """Test that certificates with different issuers are not equal"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        serial_num = 12345  # Same serial number

        # Create certificate with issuer 1
        subject1 = issuer1 = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AU"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organisation 1"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ])

        # Create certificate with issuer 2
        subject2 = issuer2 = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AU"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organisation 2"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ])

        # Build both certificates with same serial but different issuers
        cert1 = x509.CertificateBuilder().subject_name(
            subject1
        ).issuer_name(
            issuer1
        ).public_key(
            private_key.public_key()
        ).serial_number(
            serial_num
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        cert2 = x509.CertificateBuilder().subject_name(
            subject2
        ).issuer_name(
            issuer2
        ).public_key(
            private_key.public_key()
        ).serial_number(
            serial_num
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        # Write to files
        cert1_file = temp_cert_dir / "cert1.crt"
        cert2_file = temp_cert_dir / "cert2.crt"
        cert1_file.write_bytes(cert1.public_bytes(serialization.Encoding.PEM))
        cert2_file.write_bytes(cert2.public_bytes(serialization.Encoding.PEM))

        clean_to_filesystem = {
            "cert1.crt": "cert1.crt",
            "cert2.crt": "cert2.crt"
        }

        cert_obj1 = Certificate("cert1.crt", "cert1.crt", temp_cert_dir, clean_to_filesystem)
        cert_obj2 = Certificate("cert2.crt", "cert2.crt", temp_cert_dir, clean_to_filesystem)

        # They should not be equal (different issuers)
        assert cert_obj1 != cert_obj2
        assert cert_obj2 != cert_obj1  # Symmetric

    def test_certificate_not_equal_to_other_types(self, temp_cert_dir):
        """Test that certificates are not equal to other object types"""
        cert_data, cert_pem = self.create_test_certificate("test.example.com", 12345, temp_cert_dir, "cert.crt")

        clean_to_filesystem = {"cert.crt": "cert.crt"}
        cert = Certificate("cert.crt", "cert.crt", temp_cert_dir, clean_to_filesystem)

        # Should not be equal to other types
        assert cert != "string"
        assert cert != 12345
        assert cert != ["list"]
        assert cert != {"dict": "value"}
        assert cert != None

    def test_certificate_set_operations_with_duplicates(self, temp_cert_dir):
        """Test set operations with duplicate certificates (same content, different paths)"""
        # Create multiple certificates with same data (should be equal)
        serial_num = 12345
        cert1_data, cert1_pem = self.create_test_certificate("test.example.com", serial_num, temp_cert_dir, "cert1.crt")
        cert2_data, cert2_pem = self.create_test_certificate("test.example.com", serial_num, temp_cert_dir, "cert2.crt")
        cert3_data, cert3_pem = self.create_test_certificate("test.example.com", serial_num, temp_cert_dir, "cert3.crt")

        clean_to_filesystem = {
            "cert1.crt": "cert1.crt",
            "cert2.crt": "cert2.crt",
            "cert3.crt": "cert3.crt"
        }

        cert1 = Certificate("cert1.crt", "cert1.crt", temp_cert_dir, clean_to_filesystem)
        cert2 = Certificate("cert2.crt", "cert2.crt", temp_cert_dir, clean_to_filesystem)
        cert3 = Certificate("cert3.crt", "cert3.crt", temp_cert_dir, clean_to_filesystem)

        # All should be equal (same certificate content)
        assert cert1 == cert2 == cert3

        # But all should have different hashes (different full_path)
        assert hash(cert1) != hash(cert2)
        assert hash(cert2) != hash(cert3)
        assert hash(cert1) != hash(cert3)

        # Create a set - should contain ALL THREE certificates (different paths)
        cert_set = {cert1, cert2, cert3}
        assert len(cert_set) == 3  # All three should be in set due to different hashes

        # All should be in the set
        assert cert1 in cert_set
        assert cert2 in cert_set
        assert cert3 in cert_set

    def test_certificate_set_operations_with_unique_certificates(self, temp_cert_dir):
        """Test set operations with unique certificates"""
        # Create certificates with different serial numbers
        cert1_data, cert1_pem = self.create_test_certificate("test1.example.com", 11111, temp_cert_dir, "cert1.crt")
        cert2_data, cert2_pem = self.create_test_certificate("test2.example.com", 22222, temp_cert_dir, "cert2.crt")
        cert3_data, cert3_pem = self.create_test_certificate("test3.example.com", 33333, temp_cert_dir, "cert3.crt")

        clean_to_filesystem = {
            "cert1.crt": "cert1.crt",
            "cert2.crt": "cert2.crt",
            "cert3.crt": "cert3.crt"
        }

        cert1 = Certificate("cert1.crt", "cert1.crt", temp_cert_dir, clean_to_filesystem)
        cert2 = Certificate("cert2.crt", "cert2.crt", temp_cert_dir, clean_to_filesystem)
        cert3 = Certificate("cert3.crt", "cert3.crt", temp_cert_dir, clean_to_filesystem)

        # All should be different
        assert cert1 != cert2
        assert cert2 != cert3
        assert cert1 != cert3

        # Create a set - should contain all three certificates
        cert_set = {cert1, cert2, cert3}
        assert len(cert_set) == 3

        # All should be in the set
        assert cert1 in cert_set
        assert cert2 in cert_set
        assert cert3 in cert_set

    def test_certificate_set_union_operations(self, temp_cert_dir):
        """Test set union operations between certificate collections"""
        # Create collection 1
        cert1_data, cert1_pem = self.create_test_certificate("cert1.example.com", 10001, temp_cert_dir, "cert1.crt")
        cert2_data, cert2_pem = self.create_test_certificate("cert2.example.com", 10002, temp_cert_dir, "cert2.crt")
        cert3_data, cert3_pem = self.create_test_certificate("shared.example.com", 10003, temp_cert_dir, "cert3.crt")

        # Create collection 2 - cert6 has same content as cert3 but different path
        cert4_data, cert4_pem = self.create_test_certificate("cert4.example.com", 20001, temp_cert_dir, "cert4.crt")
        cert5_data, cert5_pem = self.create_test_certificate("cert5.example.com", 20002, temp_cert_dir, "cert5.crt")
        cert6_data, cert6_pem = self.create_test_certificate("shared.example.com", 10003, temp_cert_dir,
                                                             "cert6.crt")  # Same content as cert3

        clean_to_filesystem = {
            "cert1.crt": "cert1.crt", "cert2.crt": "cert2.crt", "cert3.crt": "cert3.crt",
            "cert4.crt": "cert4.crt", "cert5.crt": "cert5.crt", "cert6.crt": "cert6.crt"
        }

        cert1 = Certificate("cert1.crt", "cert1.crt", temp_cert_dir, clean_to_filesystem)
        cert2 = Certificate("cert2.crt", "cert2.crt", temp_cert_dir, clean_to_filesystem)
        cert3 = Certificate("cert3.crt", "cert3.crt", temp_cert_dir, clean_to_filesystem)
        cert4 = Certificate("cert4.crt", "cert4.crt", temp_cert_dir, clean_to_filesystem)
        cert5 = Certificate("cert5.crt", "cert5.crt", temp_cert_dir, clean_to_filesystem)
        cert6 = Certificate("cert6.crt", "cert6.crt", temp_cert_dir, clean_to_filesystem)

        # Verify shared certificates are equal but have different hashes
        assert cert3 == cert6  # Same certificate content
        assert hash(cert3) != hash(cert6)  # Different paths

        # Create two collections
        collection1 = {cert1, cert2, cert3}
        collection2 = {cert4, cert5, cert6}

        # Union should contain ALL 6 certificates (cert3 and cert6 both included due to different paths)
        union_set = collection1 | collection2
        assert len(union_set) == 6

        # All certificates should be in the union
        assert cert1 in union_set
        assert cert2 in union_set
        assert cert3 in union_set
        assert cert4 in union_set
        assert cert5 in union_set
        assert cert6 in union_set

    def test_certificate_set_intersection_operations(self, temp_cert_dir):
        """Test set intersection operations between certificate collections"""
        # Create unique certificates by path, but some with shared content
        shared1_data, shared1_pem = self.create_test_certificate("shared1.example.com", 99991, temp_cert_dir,
                                                                 "shared1a.crt")
        shared1_dup_data, shared1_dup_pem = self.create_test_certificate("shared1.example.com", 99991, temp_cert_dir,
                                                                         "shared1b.crt")

        shared2_data, shared2_pem = self.create_test_certificate("shared2.example.com", 99992, temp_cert_dir,
                                                                 "shared2a.crt")
        shared2_dup_data, shared2_dup_pem = self.create_test_certificate("shared2.example.com", 99992, temp_cert_dir,
                                                                         "shared2b.crt")

        # Create unique certificates
        unique1_data, unique1_pem = self.create_test_certificate("unique1.example.com", 88881, temp_cert_dir,
                                                                 "unique1.crt")
        unique2_data, unique2_pem = self.create_test_certificate("unique2.example.com", 88882, temp_cert_dir,
                                                                 "unique2.crt")

        clean_to_filesystem = {
            "shared1a.crt": "shared1a.crt", "shared1b.crt": "shared1b.crt",
            "shared2a.crt": "shared2a.crt", "shared2b.crt": "shared2b.crt",
            "unique1.crt": "unique1.crt", "unique2.crt": "unique2.crt"
        }

        shared1a = Certificate("shared1a.crt", "shared1a.crt", temp_cert_dir, clean_to_filesystem)
        shared1b = Certificate("shared1b.crt", "shared1b.crt", temp_cert_dir, clean_to_filesystem)
        shared2a = Certificate("shared2a.crt", "shared2a.crt", temp_cert_dir, clean_to_filesystem)
        shared2b = Certificate("shared2b.crt", "shared2b.crt", temp_cert_dir, clean_to_filesystem)
        unique1 = Certificate("unique1.crt", "unique1.crt", temp_cert_dir, clean_to_filesystem)
        unique2 = Certificate("unique2.crt", "unique2.crt", temp_cert_dir, clean_to_filesystem)

        # Verify shared certificates are equal but have different hashes
        assert shared1a == shared1b
        assert shared2a == shared2b
        assert hash(shared1a) != hash(shared1b)  # Different paths
        assert hash(shared2a) != hash(shared2b)  # Different paths

        # Create two collections with no overlapping paths
        collection1 = {shared1a, shared2a, unique1}
        collection2 = {shared1b, shared2b, unique2}

        # Intersection should be EMPTY because no shared paths (hash-based)
        intersection_set = collection1 & collection2
        assert len(intersection_set) == 0

        # Even though certificates are equal by content, they're different by path/hash
        assert shared1a not in collection2  # Different object, different path
        assert shared1b not in collection1  # Different object, different path

    def test_certificate_set_difference_operations(self, temp_cert_dir):
        """Test set difference operations between certificate collections"""
        # Create certificates for collection 1
        cert1_data, cert1_pem = self.create_test_certificate("only1.example.com", 11111, temp_cert_dir, "cert1.crt")
        cert2_data, cert2_pem = self.create_test_certificate("only1b.example.com", 11112, temp_cert_dir, "cert2.crt")
        shared_data, shared_pem = self.create_test_certificate("shared.example.com", 99999, temp_cert_dir,
                                                               "shared1.crt")

        # Create certificates for collection 2
        cert3_data, cert3_pem = self.create_test_certificate("only2.example.com", 22221, temp_cert_dir, "cert3.crt")
        cert4_data, cert4_pem = self.create_test_certificate("only2b.example.com", 22222, temp_cert_dir, "cert4.crt")
        shared_dup_data, shared_dup_pem = self.create_test_certificate("shared.example.com", 99999, temp_cert_dir,
                                                                       "shared2.crt")

        clean_to_filesystem = {
            "cert1.crt": "cert1.crt", "cert2.crt": "cert2.crt", "shared1.crt": "shared1.crt",
            "cert3.crt": "cert3.crt", "cert4.crt": "cert4.crt", "shared2.crt": "shared2.crt"
        }

        cert1 = Certificate("cert1.crt", "cert1.crt", temp_cert_dir, clean_to_filesystem)
        cert2 = Certificate("cert2.crt", "cert2.crt", temp_cert_dir, clean_to_filesystem)
        shared1 = Certificate("shared1.crt", "shared1.crt", temp_cert_dir, clean_to_filesystem)
        cert3 = Certificate("cert3.crt", "cert3.crt", temp_cert_dir, clean_to_filesystem)
        cert4 = Certificate("cert4.crt", "cert4.crt", temp_cert_dir, clean_to_filesystem)
        shared2 = Certificate("shared2.crt", "shared2.crt", temp_cert_dir, clean_to_filesystem)

        # Verify shared certificates are equal but have different hashes (different paths)
        assert shared1 == shared2
        assert hash(shared1) != hash(shared2)

        # Create collections
        collection1 = {cert1, cert2, shared1}
        collection2 = {cert3, cert4, shared2}

        # Difference should contain ALL certificates from collection1
        # (no path overlap with collection2, even though shared1 == shared2)
        diff_set = collection1 - collection2
        assert len(diff_set) == 3  # All certificates in collection1
        assert cert1 in diff_set
        assert cert2 in diff_set
        assert shared1 in diff_set  # shared1 stays because it has different path than shared2

        # Similarly, collection2 - collection1 should contain all of collection2
        diff_set2 = collection2 - collection1
        assert len(diff_set2) == 3  # All certificates in collection2
        assert cert3 in diff_set2
        assert cert4 in diff_set2
        assert shared2 in diff_set2  # shared2 stays because it has different path than shared1

        # Symmetric difference should contain ALL certificates from both collections
        # (no overlapping paths)
        sym_diff_set = collection1 ^ collection2
        assert len(sym_diff_set) == 6  # All certificates from both collections
        assert cert1 in sym_diff_set
        assert cert2 in sym_diff_set
        assert shared1 in sym_diff_set
        assert cert3 in sym_diff_set
        assert cert4 in sym_diff_set
        assert shared2 in sym_diff_set

    def test_certificate_hash_consistency(self, temp_cert_dir):
        """Test that certificate hashes are consistent across multiple calls"""
        cert_data, cert_pem = self.create_test_certificate("test.example.com", 12345, temp_cert_dir, "cert.crt")

        clean_to_filesystem = {"cert.crt": "cert.crt"}
        cert = Certificate("cert.crt", "cert.crt", temp_cert_dir, clean_to_filesystem)

        # Hash should be consistent across multiple calls
        hash1 = hash(cert)
        hash2 = hash(cert)
        hash3 = hash(cert)

        assert hash1 == hash2 == hash3

    def test_certificate_equality_reflexivity(self, temp_cert_dir):
        """Test that certificate equality is reflexive (a == a)"""
        cert_data, cert_pem = self.create_test_certificate("test.example.com", 12345, temp_cert_dir, "cert.crt")

        clean_to_filesystem = {"cert.crt": "cert.crt"}
        cert = Certificate("cert.crt", "cert.crt", temp_cert_dir, clean_to_filesystem)

        # Should be equal to itself
        assert cert == cert
        assert not (cert != cert)

    def test_certificate_equality_transitivity(self, temp_cert_dir):
        """Test that certificate equality is transitive (if a == b and b == c, then a == c)"""
        serial_num = 12345
        cert1_data, cert1_pem = self.create_test_certificate("test.example.com", serial_num, temp_cert_dir, "cert1.crt")
        cert2_data, cert2_pem = self.create_test_certificate("test.example.com", serial_num, temp_cert_dir, "cert2.crt")
        cert3_data, cert3_pem = self.create_test_certificate("test.example.com", serial_num, temp_cert_dir, "cert3.crt")

        clean_to_filesystem = {
            "cert1.crt": "cert1.crt",
            "cert2.crt": "cert2.crt",
            "cert3.crt": "cert3.crt"
        }

        cert1 = Certificate("cert1.crt", "cert1.crt", temp_cert_dir, clean_to_filesystem)
        cert2 = Certificate("cert2.crt", "cert2.crt", temp_cert_dir, clean_to_filesystem)
        cert3 = Certificate("cert3.crt", "cert3.crt", temp_cert_dir, clean_to_filesystem)

        # Test transitivity
        assert cert1 == cert2
        assert cert2 == cert3
        assert cert1 == cert3  # Transitivity

    def test_large_certificate_set_performance(self, temp_cert_dir):
        """Test performance with larger sets of certificates"""
        certificates = []
        clean_to_filesystem = {}

        # Create 50 certificates with unique paths and some duplicate content
        for i in range(50):
            serial_num = (i // 5) + 1  # This creates duplicates (5 certs per serial number), starting from 1
            filename = f"cert_{i}.crt"
            cert_data, cert_pem = self.create_test_certificate(f"test{serial_num}.example.com", serial_num,
                                                               temp_cert_dir, filename)
            clean_to_filesystem[filename] = filename

            cert = Certificate(filename, filename, temp_cert_dir, clean_to_filesystem)
            certificates.append(cert)

        # Convert to set - should contain ALL certificates (unique paths)
        cert_set = set(certificates)

        # Should have 50 certificates (all have unique paths, so all in set)
        assert len(cert_set) == 50

        # Test set operations
        half1 = set(certificates[:25])
        half2 = set(certificates[25:])

        union = half1 | half2
        assert len(union) == 50  # All certificates (unique paths)

        # Intersection should be empty (no overlapping paths)
        intersection = half1 & half2
        assert len(intersection) == 0  # No shared paths between halves


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
                                                                      "cert2.crt")  # Same as cert1
        cert3_data, cert3_pem = test_instance.create_test_certificate("test3.example.com", 33333, temp_dir,
                                                                      "cert3.crt")  # Different

        clean_to_filesystem = {
            "cert1.crt": "cert1.crt",
            "cert2.crt": "cert2.crt",
            "cert3.crt": "cert3.crt"
        }

        cert1 = Certificate("cert1.crt", "cert1.crt", temp_dir, clean_to_filesystem)
        cert2 = Certificate("cert2.crt", "cert2.crt", temp_dir, clean_to_filesystem)
        cert3 = Certificate("cert3.crt", "cert3.crt", temp_dir, clean_to_filesystem)

        # Create collections for testing
        collection1 = {cert1, cert2}  # Should only contain 1 unique cert
        collection2 = {cert2, cert3}  # Should contain 2 certs

        pass  # Put breakpoint here to inspect equality and set operations

    finally:
        shutil.rmtree(temp_dir)


if __name__ == "__main__":
    sample_equality_test_data()