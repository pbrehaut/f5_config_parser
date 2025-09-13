from f5_config_parser.stanza.generic import ConfigStanza
from typing import TYPE_CHECKING, List
import hashlib

if TYPE_CHECKING:
    from f5_config_parser.collection import StanzaCollection


class CliAdminPartitionsStanza(ConfigStanza):
    """CLI admin-partitions stanza with unique path generation for duplicate handling"""

    def _discover_dependencies(self, collection: 'StanzaCollection') -> List[str]:
        """CLI admin-partitions stanzas typically don't have dependencies"""
        return []

    @property
    def full_path(self) -> str:
        """Override to generate unique path based on content for duplicate handling"""
        base_path = f"{' '.join(self.prefix)} {self.name}"

        # Extract unique identifier from config lines
        unique_identifier = self._extract_unique_identifier()

        if unique_identifier:
            return f"{base_path}#{unique_identifier}"
        else:
            # Fallback to content hash if no clear identifier found
            content_hash = self._generate_content_hash()
            return f"{base_path}#{content_hash}"

    @property
    def original_path(self) -> str:
        """Get the original path without unique identifier suffix"""
        return f"{' '.join(self.prefix)} {self.name}"

    def _extract_unique_identifier(self) -> str:
        """Extract unique identifier from config lines (e.g., partition name)"""
        for line in self.config_lines:
            line = line.strip()

            # Look for update-partition commands
            if line.startswith('update-partition'):
                parts = line.split()
                if len(parts) >= 2:
                    partition_name = parts[1]
                    return f"partition_{partition_name}"

            # Look for other potential unique identifiers
            # Add more patterns as needed for different CLI admin-partitions content

        return ""

    def _generate_content_hash(self) -> str:
        """Generate a short hash from config content as fallback identifier"""
        # Create a stable representation of the config content
        content_str = '\n'.join(sorted([line.strip() for line in self.config_lines if line.strip()]))

        # Generate short hash (first 8 characters should be sufficient for uniqueness)
        content_hash = hashlib.md5(content_str.encode()).hexdigest()[:8]
        return f"hash_{content_hash}"

    def __str__(self) -> str:
        """Return F5 configuration format using original path (without unique suffix)"""
        if self.config_lines:
            lines = [f"{self.original_path} {{"]
            lines.extend(self.config_lines)
            lines.append("}")
            return '\n'.join(lines) + '\n'
        else:
            return f"{self.original_path} {{ }}\n"

    def get_partition_name(self) -> str:
        """Convenience method to extract the partition name from update-partition command"""
        for line in self.config_lines:
            line = line.strip()
            if line.startswith('update-partition'):
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1]
        return ""

    def __repr__(self):
        partition_name = self.get_partition_name()
        if partition_name:
            return f"<{self.__class__.__name__} partition='{partition_name}' @ {self.original_path}>"
        else:
            return f"<{self.__class__.__name__} '{self.name}' @ {self.original_path}>"