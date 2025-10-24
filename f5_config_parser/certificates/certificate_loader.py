"""Functions for F5 certificate extraction and parsing"""

import tarfile
import tempfile
from pathlib import Path
import re
import shutil
from typing import List
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from f5_config_parser.certificates.certificate import Certificate


def extract_tar(tar_path: str) -> Path:
    """Extract tar to temporary directory and return extraction path"""
    tar_path = Path(tar_path)

    if not tar_path.exists():
        raise FileNotFoundError(f"Tar file not found: {tar_path}")

    # Create temporary directory
    extract_dir = Path(tempfile.mkdtemp(prefix="f5_certs_"))

    try:
        # Extract with Windows-safe filenames
        with tarfile.open(tar_path, 'r') as tar:
            for member in tar.getmembers():
                if member.isfile():
                    # Sanitise filename for Windows
                    safe_name = member.name.replace(':', '_COLON_')
                    target_path = extract_dir / safe_name
                    target_path.parent.mkdir(parents=True, exist_ok=True)

                    # Extract file content
                    file_obj = tar.extractfile(member)
                    if file_obj:
                        target_path.write_bytes(file_obj.read())
    except (tarfile.TarError, OSError) as e:
        raise ValueError(f"Failed to extract tar file {tar_path}: {e}")

    return extract_dir


def parse_f5_filename(filesystem_filename: str) -> tuple[str, str]:
    """
    Convert filesystem filename to (file_type, clean_f5_name) tuple

    Returns:
        tuple: (file_type, clean_f5_name) where file_type is 'certificate', 'key', etc.
    """
    # Remove version suffix like _93973_1
    pattern = r'^(.+)_\d+_\d+$'
    match = re.match(pattern, filesystem_filename)

    if not match:
        raise ValueError(f"Cannot parse F5 filename: {filesystem_filename}")

    base_filename = match.group(1)

    # Convert back from sanitised
    clean_name = base_filename.replace('_COLON_', ':')

    # Extract F5 path from structure like: files_d/Common_d/certificate_d/:Common:filename
    parts = clean_name.replace('\\', '/').split('/')

    # Find the directory type (certificate_d, certificate_key_d, etc.)
    file_type = None
    for part in parts:
        if part == 'certificate_d':
            file_type = 'certificate'
            break
        elif part == 'certificate_key_d':
            file_type = 'key'
            break

    if not file_type:
        raise ValueError(f"No recognised file type directory found in: {filesystem_filename}")

    # Find the F5 name part (contains colons)
    f5_part = None
    for part in parts:
        if ':' in part:
            f5_part = part
            break

    if not f5_part:
        raise ValueError(f"No F5 path found in: {filesystem_filename}")

    # Convert :Common:filename to /Common/filename
    clean_f5_name = f5_part.replace(':', '/')

    return (file_type, clean_f5_name)


def build_filename_mappings(extract_dir: Path) -> tuple[dict, dict]:
    """
    Build mappings between filesystem and clean filenames using tuple keys

    Returns:
        tuple: (filesystem_to_clean, clean_to_filesystem) where keys are (file_type, name) tuples
    """
    filesystem_to_clean = {}
    clean_to_filesystem = {}

    for file_path in extract_dir.rglob('*'):
        if file_path.is_file():
            filesystem_filename = str(file_path.relative_to(extract_dir))

            try:
                file_type, clean_f5_name = parse_f5_filename(filesystem_filename)
                tuple_key = (file_type, clean_f5_name)

                filesystem_to_clean[filesystem_filename] = tuple_key
                clean_to_filesystem[tuple_key] = filesystem_filename

            except ValueError as e:
                print(f"Skipping unparseable file: {e}")

    return filesystem_to_clean, clean_to_filesystem


def load_certificates_from_tar(tar_file_path: str, load_pem_data: bool = False) -> List[Certificate]:
    """
    Load certificate objects from F5 tar file

    Args:
        tar_file_path: Path to the F5 configuration tar file
        load_pem_data: Whether to load the actual PEM data into certificate objects

    Returns:
        List of Certificate objects
    """
    extract_dir = None

    try:
        # Extract tar file to temporary directory
        extract_dir = extract_tar(tar_file_path)

        # Build filename mappings
        filesystem_to_clean, clean_to_filesystem = build_filename_mappings(extract_dir)

        # Find all certificate files
        cert_tuples = [tuple_key for tuple_key in clean_to_filesystem.keys()
                       if tuple_key[0] == 'certificate']

        print(f"Found {len(cert_tuples)} certificate files")

        # Load each certificate
        certificates = []
        for cert_tuple in cert_tuples:
            file_type, cert_filename = cert_tuple
            cert_filesystem_filename = clean_to_filesystem[cert_tuple]

            # Look for matching key
            key_tuple = ('key', cert_filename.replace('.crt', '.key'))
            key_filename = None
            key_pem_data = None

            if key_tuple in clean_to_filesystem:
                key_filename = cert_filename.replace('.crt', '.key')
                key_filesystem_filename = clean_to_filesystem[key_tuple]

                # Load key PEM data if requested
                if load_pem_data:
                    key_path = extract_dir / key_filesystem_filename
                    try:
                        key_pem_data = key_path.read_text(encoding='utf-8')
                    except (ValueError, IOError) as e:
                        print(f"Warning: Failed to load key PEM data for {cert_filename}: {e}")

            # Load certificate from file
            cert_path = extract_dir / cert_filesystem_filename
            try:
                cert_data = cert_path.read_bytes()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())

                # Get PEM data if requested
                cert_pem_data = None
                if load_pem_data:
                    cert_pem_data = cert_data.decode('utf-8')

                # Create Certificate object
                certificate = Certificate(
                    cert_filename,
                    cert,
                    cert_pem_data=cert_pem_data,
                    key_filename=key_filename,
                    key_pem_data=key_pem_data
                )
                certificates.append(certificate)

            except ValueError as e:
                print(f"Failed to load certificate {cert_filename}: {e}")
            except FileNotFoundError as e:
                print(f"Failed to find certificate file {cert_filename}: {e}")

        print(f"Loaded {len(certificates)} certificates")
        return certificates

    finally:
        # Always clean up temporary extraction directory
        if extract_dir and extract_dir.exists():
            shutil.rmtree(extract_dir)