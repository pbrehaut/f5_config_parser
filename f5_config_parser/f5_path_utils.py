"""Utility functions for F5 archive path manipulation"""
from typing import Optional


def rename_f5_archive_path(
    original_path: str,
    source_filename: str,
    new_partition: str,
    new_name: str,
    dir_separator: str = "\\",
    colon_format: str = "_COLON_"
) -> Optional[str]:
    """
    Replace partition and certificate name in F5 archive paths.

    Args:
        original_path: Original archive path to transform
        source_filename: Source filename like '/Partition/filename.ext' to extract old values from
        new_partition: New partition name
        new_name: New name (without extension)
        dir_separator: Directory separator ('\\' for Windows-style, '/' for Unix-style)
        colon_format: Colon format ('_COLON_' or ':')

    Returns:
        Updated path with new partition and name, or None if original_path is None/empty
    """
    if not original_path:
        return None

    # Determine certificate type directory
    cert_type_dir = "certificate_key_d" if "certificate_key_d" in original_path else "certificate_d"

    # Extract partition and filename from source
    parts = source_filename.split('/')
    old_partition = parts[1] if len(parts) > 1 else ''
    old_full_name = '/'.join(parts[2:]) if len(parts) > 2 else source_filename

    # Replace partition directory: files_d\old_partition_d\cert_type_d\ -> files_d\new_partition_d\cert_type_d\
    old_dir_pattern = f"files_d{dir_separator}{old_partition}_d{dir_separator}{cert_type_dir}{dir_separator}"
    new_dir_pattern = f"files_d{dir_separator}{new_partition}_d{dir_separator}{cert_type_dir}{dir_separator}"
    result = original_path.replace(old_dir_pattern, new_dir_pattern)

    # Replace the name pattern: COLON_partition_COLON_oldname_ -> COLON_partition_COLON_newname_
    old_name_pattern = f"{colon_format}{old_partition}{colon_format}{old_full_name}_"
    new_name_pattern = f"{colon_format}{new_partition}{colon_format}{new_name}_"
    result = result.replace(old_name_pattern, new_name_pattern)

    return result