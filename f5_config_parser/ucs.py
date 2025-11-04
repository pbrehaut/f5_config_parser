# f5_config_parser/ucs.py
"""UCS archive handling for F5 configuration management."""

import os
import tarfile
import tempfile
import shutil
from typing import List, Dict
from pathlib import Path

from f5_config_parser.collection import StanzaCollection
from f5_config_parser.certificates.certificate_loader import load_certificates_from_tar


class UCS:
    """Handles UCS archive extraction, collection initialization, and reconstruction."""

    def __init__(self, ucs_path: str):
        """Initialise UCS handler.

        Args:
            ucs_path: Path to the UCS archive file
        """
        self.ucs_path = ucs_path
        self.config_files: List[str] = []
        self.tmsh_headers: Dict[str, str] = {}
        self.extracted_dir = None
        self._extract_and_discover_files()

    def _extract_and_discover_files(self):
        """Extract UCS archive and discover all config files."""
        self.extracted_dir = tempfile.mkdtemp(prefix='ucs_')

        # Extract with sanitised filenames (like certificate loader)
        with tarfile.open(self.ucs_path, 'r') as tar:
            for member in tar.getmembers():
                if member.isfile():
                    # Sanitise filename for Windows compatibility
                    safe_name = member.name.replace(':', '_COLON_')
                    target_path = os.path.join(self.extracted_dir, safe_name)
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)

                    # Extract file content
                    file_obj = tar.extractfile(member)
                    if file_obj:
                        with open(target_path, 'wb') as f:
                            f.write(file_obj.read())

        # Discover config files in order
        self._discover_config_files()

    def _discover_config_files(self):
        """Discover all bigip.conf, bigip_base.conf, and bigip_gtm.conf files."""
        # Add Common partition configs first
        common_config = 'config/bigip.conf'
        common_config_path = os.path.join(self.extracted_dir, common_config)
        if os.path.exists(common_config_path):
            self.config_files.append(common_config)

        common_base_config = 'config/bigip_base.conf'
        common_base_config_path = os.path.join(self.extracted_dir, common_base_config)
        if os.path.exists(common_base_config_path):
            self.config_files.append(common_base_config)

        common_gtm_config = 'config/bigip_gtm.conf'
        common_gtm_config_path = os.path.join(self.extracted_dir, common_gtm_config)
        if os.path.exists(common_gtm_config_path):
            self.config_files.append(common_gtm_config)

        # Discover partition configs
        partitions_dir = os.path.join(self.extracted_dir, 'config', 'partitions')
        if os.path.exists(partitions_dir):
            for partition_name in sorted(os.listdir(partitions_dir)):
                partition_dir = os.path.join(partitions_dir, partition_name)
                if os.path.isdir(partition_dir):
                    # Add bigip.conf first, then bigip_base.conf, then bigip_gtm.conf for each partition
                    partition_config = f'config/partitions/{partition_name}/bigip.conf'
                    partition_config_path = os.path.join(self.extracted_dir, partition_config)
                    if os.path.isfile(partition_config_path):
                        self.config_files.append(partition_config)

                    partition_base_config = f'config/partitions/{partition_name}/bigip_base.conf'
                    partition_base_config_path = os.path.join(self.extracted_dir, partition_base_config)
                    if os.path.isfile(partition_base_config_path):
                        self.config_files.append(partition_base_config)

                    partition_gtm_config = f'config/partitions/{partition_name}/bigip_gtm.conf'
                    partition_gtm_config_path = os.path.join(self.extracted_dir, partition_gtm_config)
                    if os.path.isfile(partition_gtm_config_path):
                        self.config_files.append(partition_gtm_config)

    def _read_config_file(self, config_file: str) -> str:
        """Read a single config file and store TMSH header if present.

        Args:
            config_file: Relative path to config file within archive

        Returns:
            Config file contents as string
        """
        config_path = os.path.join(self.extracted_dir, config_file)
        with open(config_path, 'r') as f:
            content = f.read()

        # Extract and store TMSH header
        lines = content.split('\n')
        if lines and lines[0].startswith('#TMSH-VERSION:'):
            # Store header line plus blank line if present
            if len(lines) > 1 and lines[1] == '':
                self.tmsh_headers[config_file] = lines[0] + '\n\n'
            else:
                self.tmsh_headers[config_file] = lines[0] + '\n'

        return content

    def _get_full_config_for_hash(self) -> str:
        """Get concatenated config for cache hashing.

        Returns:
            All config files concatenated together for hash calculation
        """
        configs = []
        for config_file in self.config_files:
            config_text = self._read_config_file(config_file)
            configs.append(config_text)
        return ''.join(configs)

    def load_collection(self) -> StanzaCollection:
        """Load and initialise StanzaCollection from UCS archive.

        Returns:
            Initialised StanzaCollection with config objects and certificates
        """
        # Get full concatenated config for cache hashing
        full_config = self._get_full_config_for_hash()

        # Create empty collection with full config hash
        combined_collection = StanzaCollection([], config_hash_str=full_config)

        # Parse each config file separately and merge
        for config_file in self.config_files:
            config_text = self._read_config_file(config_file)
            file_collection = StanzaCollection.from_config(
                config_text,
                initialise=False,  # Don't initialise per-file
                source_config_file=config_file
            )
            combined_collection.__iadd__(file_collection, log_additions=False)

        # Add certificates
        certificates = load_certificates_from_tar(self.ucs_path, load_pem_data=True)
        combined_collection.__iadd__(certificates, log_additions=False)

        # Initialise once on the combined collection
        combined_collection.initialise_ip_to_rd()
        combined_collection.initialise_dependencies()
        combined_collection.save_dependency_cache()

        return combined_collection

    def _group_stanzas_by_file(self, collection: StanzaCollection) -> Dict[str, list]:
        """Group stanzas by source_config_file, excluding certificates.

        Certificates are handled separately and should not be written to config files.

        Args:
            collection: StanzaCollection to group

        Returns:
            Dictionary mapping config file paths to lists of stanzas

        Raises:
            ValueError: If any non-certificate stanza is missing source_config_file attribute
        """
        stanzas_by_file = {}
        for stanza in collection.stanzas:
            # Skip certificate objects - they're handled separately
            if getattr(stanza, 'prefix', None) == ('certificate', 'object'):
                continue

            source_file = getattr(stanza, 'source_config_file', None)
            if source_file is None:
                raise ValueError(
                    f"Stanza {stanza.full_path} is missing source_config_file attribute. "
                    f"All stanzas must have source_config_file set for UCS write-back."
                )
            if source_file not in stanzas_by_file:
                stanzas_by_file[source_file] = []
            stanzas_by_file[source_file].append(stanza)
        return stanzas_by_file

    def _write_certificates(self, collection: StanzaCollection):
        """Write certificates back to archive.

        Args:
            collection: StanzaCollection containing certificates
        """
        for cert in collection.filter(('certificate', 'object')):
            if cert.pem_data:
                cert_path = os.path.join(self.extracted_dir, cert.original_cert_filename)
                os.makedirs(os.path.dirname(cert_path), exist_ok=True)
                with open(cert_path, 'w') as f:
                    f.write(cert.pem_data)
            if cert.key_pem_data:
                key_path = os.path.join(self.extracted_dir, cert.original_key_filename)
                os.makedirs(os.path.dirname(key_path), exist_ok=True)
                with open(key_path, 'w') as f:
                    f.write(cert.key_pem_data)

    def write_back_collection(self, collection: StanzaCollection, output_path: str):
        """Write modified collection back to new UCS archive.

        Only config files with matching stanzas in the collection will be overwritten.
        Files without matching stanzas remain untouched, allowing selective updates.

        Args:
            collection: Modified StanzaCollection
            output_path: Path for output UCS file
        """
        # Group stanzas by source file
        stanzas_by_file = self._group_stanzas_by_file(collection)

        # Write config files only if they have stanzas in the collection
        for config_file, stanzas in stanzas_by_file.items():
            # Only write if we have stanzas for this file
            if not stanzas:
                continue

            # Create sub-collection and serialise
            file_collection = StanzaCollection(stanzas)
            config_text = str(file_collection)

            # Prepend TMSH header if we have one
            if config_file in self.tmsh_headers:
                config_text = self.tmsh_headers[config_file] + config_text

            # Write to extracted directory
            config_path = os.path.join(self.extracted_dir, config_file)
            with open(config_path, 'w') as f:
                f.write(config_text)

        # Write certificates
        self._write_certificates(collection)

        # Rebuild archive
        self._save_archive(output_path)

    def _save_archive(self, output_path: str):
        """Rebuild UCS archive from extracted directory.

        Args:
            output_path: Path for output UCS file
        """
        with tarfile.open(output_path, 'w') as tar:
            for root, dirs, files in os.walk(self.extracted_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, self.extracted_dir)
                    # Convert sanitised filenames back to original with colons
                    arcname = arcname.replace('_COLON_', ':')
                    tar.add(file_path, arcname=arcname)

    def cleanup(self):
        """Remove temporary extracted directory."""
        if self.extracted_dir and os.path.exists(self.extracted_dir):
            shutil.rmtree(self.extracted_dir)

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.cleanup()