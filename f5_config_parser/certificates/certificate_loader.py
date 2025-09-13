"""Functions for F5 certificate extraction and parsing"""

import tarfile
import tempfile
from pathlib import Path
import re
import shutil
from typing import List
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


def parse_f5_filename(filesystem_filename: str) -> str:
    """Convert filesystem filename to clean F5 name"""
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

    return clean_f5_name


def build_filename_mappings(extract_dir: Path) -> tuple[dict, dict]:
    """Build mappings between filesystem and clean filenames"""
    filesystem_to_clean = {}
    clean_to_filesystem = {}

    for file_path in extract_dir.rglob('*'):
        if file_path.is_file():
            filesystem_filename = str(file_path.relative_to(extract_dir))

            try:
                clean_filename = parse_f5_filename(filesystem_filename)
                filesystem_to_clean[filesystem_filename] = clean_filename
                clean_to_filesystem[clean_filename] = filesystem_filename

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

        # Find all certificate files (include .crt, .key, .pem)
        cert_files = [clean_name for clean_name in clean_to_filesystem.keys()
                      if clean_name.endswith(('.crt', '.key', '.pem'))]

        print(f"Found {len(cert_files)} certificate files")

        # Load each certificate
        certificates = []
        for clean_filename in cert_files:
            filesystem_filename = clean_to_filesystem[clean_filename]

            try:
                cert = Certificate(clean_filename, filesystem_filename, extract_dir,
                                 clean_to_filesystem, load_pem_data=load_pem_data)
                certificates.append(cert)
            except ValueError as e:
                print(f"Failed to load certificate {clean_filename}: {e}")

        print(f"Loaded {len(certificates)} certificates")
        return certificates

    finally:
        # Always clean up temporary extraction directory
        if extract_dir and extract_dir.exists():
            shutil.rmtree(extract_dir)