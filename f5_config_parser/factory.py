import re
from typing import List, Tuple, Optional
from f5_config_parser.stanza import (
    ConfigStanza,
    GenericStanza,
    VirtualServerStanza,
    PoolStanza,
    NodeStanza,
    IRuleStanza,
    CliAdminPartitionsStanza,
    SysFileCrtStanza,
    SslProfileStanza,
    DataGroupStanza,
    SelfIPStanza,
    RouteStanza,
    VlanStanza,
    SNATPoolStanza,
    HTTPSMonitorStanza,
    WideIPStanza,
    GTMPoolStanza,
    GTMServerStanza,
)


class StanzaFactory:
    """Factory for parsing F5 configuration text into ConfigStanza objects"""

    # Known F5 module prefixes
    F5_MODULE_PREFIXES = {
        'asm', 'apm', 'auth', 'cli', 'cm', 'gtm',
        'ltm', 'net', 'pem', 'security', 'sys', 'wom'
    }

    # Generic pattern for most stanzas - anchored at start of line
    # Used in verification stage for checking if any stanza heading are missed by the pattern below
    STANZA_HEADER_PATTERN = re.compile(r'^([\w-]+(?:\s+[\w-]+)*)\s+(\S+)\s+\{($|\s+\}$)')

    # F5-specific pattern for when we need to be more careful (like inside iRules)
    # Dynamically built from F5_MODULE_PREFIXES
    F5_STANZA_HEADER_PATTERN = re.compile(
        rf'^({"|".join(F5_MODULE_PREFIXES)})(?:\s+[\w-]+)*\s+(\S+)\s*\{{')

    @classmethod
    def parse_stanzas(cls, raw_config: str) -> List[ConfigStanza]:
        """
        Parse entire F5 configuration text into list of ConfigStanza objects.

        Args:
            raw_config: Complete F5 configuration as string

        Returns:
            List of parsed ConfigStanza objects
        """
        lines = raw_config.strip().split('\n')
        stanzas = []
        i = 0

        while i < len(lines):
            # Look for stanza header
            header_match = cls.F5_STANZA_HEADER_PATTERN.match(lines[i].rstrip())

            if header_match:
                all_words = [x for x in lines[i].split() if x != '}' and x != '{']
                prefix_tuple = tuple(all_words[:-1])
                name = all_words[-1]

                # Find the end of this stanza using context-aware parsing
                stanza_end = cls._find_stanza_end(lines, i + 1, prefix_tuple)

                # Extract content lines (everything between header and end)
                content_lines = lines[i:stanza_end]

                # Remove the closing brace if present
                content_lines = cls._clean_content_lines(content_lines)

                # Create the stanza
                stanza = cls._create_stanza(prefix_tuple, name, content_lines)
                stanzas.append(stanza)

                # Move to next stanza
                i = stanza_end
            else:
                # Skip non-stanza lines (comments, empty lines, etc.)
                i += 1

        return stanzas

    @classmethod
    def _find_stanza_end(cls, lines: List[str], start_index: int, current_stanza_type: Tuple[str, ...]) -> int:
        """
        Find the end of current stanza using context-aware pattern matching.

        Args:
            lines: All configuration lines
            start_index: Index to start searching from
            current_stanza_type: Current stanza prefix tuple for context

        Returns:
            Index where current stanza ends
        """
        pattern = cls.F5_STANZA_HEADER_PATTERN

        for i in range(start_index, len(lines)):
            line = lines[i]

            # Check if this line starts a new stanza using appropriate pattern
            if pattern.match(line.rstrip()):
                return i

        # If no next stanza found, end is EOF
        return len(lines)

    @classmethod
    def _clean_content_lines(cls, content_lines: List[str]) -> List[str]:
        """
        Clean up content lines by removing trailing empty lines only.
        Keep the closing brace as it's part of the F5 configuration structure.

        Args:
            content_lines: Raw content lines from stanza

        Returns:
            Cleaned content lines with closing brace preserved
        """
        # Remove trailing empty lines and closing braces
        while content_lines and content_lines[-1].strip() == '':
            content_lines.pop()

        # Remove only the final closing brace if it exists and is alone on the line
        if content_lines and content_lines[-1].strip() == '}':
            content_lines.pop()

        return content_lines

    @classmethod
    def _create_stanza(cls, prefix: Tuple[str, ...], name: str, content_lines: List[str]) -> ConfigStanza:
        """
        Create appropriate stanza type based on prefix.

        Args:
            prefix: Parsed prefix tuple (e.g., ("ltm", "pool"))
            name: Stanza name
            content_lines: Configuration content lines

        Returns:
            ConfigStanza instance (specific type or GenericStanza)
        """
        # Registry of specific stanza types
        registry = {
            ("cli",): CliAdminPartitionsStanza,
            ("ltm", "pool"): PoolStanza,
            ("ltm", "node"): NodeStanza,
            ("ltm", "virtual"): VirtualServerStanza,
            ("ltm", "rule"): IRuleStanza,
            ("ltm", "snatpool"): SNATPoolStanza,
            ("sys", "file", "ssl-cert"): SysFileCrtStanza,
            ("ltm", "profile", "client-ssl"): SslProfileStanza,
            ("ltm", "profile", "server-ssl"): SslProfileStanza,
            ("ltm", "monitor", "https"): HTTPSMonitorStanza,
            ("ltm", "data-group", "internal"): DataGroupStanza,
            ("net", "self"): SelfIPStanza,
            ("net", "route"): RouteStanza,
            ("net", "vlan"): VlanStanza,
            ("gtm", "wideip", "a"): WideIPStanza,
            ("gtm", "pool", "a"): GTMPoolStanza,
            ("gtm", "server"): GTMServerStanza,
            ("security", "protocol-inspection", "compliance-objects"): CliAdminPartitionsStanza,
        }
        stanza_class = registry.get(prefix, GenericStanza)
        return stanza_class(prefix, name, content_lines)
