from typing import List, Optional, Tuple, Union, Dict, Any, Literal
import re
import uuid
from datetime import datetime
from typing import TYPE_CHECKING
from f5_config_parser.change_record import ChangeRecord
from f5_config_parser.monitored_list import MonitoredList

if TYPE_CHECKING:
    from f5_config_parser.collection import StanzaCollection


class ConfigStanza:
    """Base class for F5 configuration stanzas"""
    def __init__(
            self,
            prefix: Tuple[str, ...],
            name: str,
            config_lines: List[str]
    ):
        self.prefix = prefix
        self.name = name
        self._changes: List[ChangeRecord] = []
        self._parsed_config: Optional[Dict[str, Any]] = None
        self._dependencies: Optional[List[str]] = None
        self._dependents: Optional[List[str]] = None

        # Compute and store frozen content hash for stable equality/hashing
        normalised_content = '\n'.join(
            [self.normalise_line(line) for line in config_lines if self.normalise_line(line)])
        self._frozen_content_hash = hash(normalised_content)

        # Use the property setter to initialise
        self.config_lines = config_lines

    def __hash__(self) -> int:
        """Hash based on full path and frozen content from initialisation"""
        return hash((self.full_path, self._frozen_content_hash))

    def __eq__(self, other) -> bool:
        """
        Compare stanzas based on type:
        - When compared to string: compare full_path only (for set operations and filtering)
        - When compared to ConfigStanza: compare full_path AND initial content (frozen at creation)
        """
        if isinstance(other, str):
            return self.full_path == other
        elif isinstance(other, ConfigStanza):
            return (self.full_path == other.full_path and
                    self._frozen_content_hash == other._frozen_content_hash)
        else:
            return False

    def __repr__(self):
        return f"<{self.__class__.__name__} '{self.name}' @ {self.full_path.replace(self.name, '')}>"

    def __str__(self):
        """Return F5 configuration format with full path and braces"""
        if self.config_lines:
            lines = [f"{self.full_path} {{"]
            lines.extend(self.config_lines)
            lines.append("}")
            return '\n'.join(lines) + '\n'
        else:
            lines = f"{self.full_path} {{ }}\n"
            return lines

    def __lt__(self, other):
        """Sort by full_path attribute"""
        if not isinstance(other, ConfigStanza):
            return NotImplemented

        return self.full_path < other.full_path

    def has_same_content(self, other, normalise_whitespace: bool = True) -> bool:
        """
        Check if two stanzas have identical configuration content.

        Args:
            normalise_whitespace: If True, strips leading/trailing whitespace and
                                 reduces multiple spaces to single spaces. If False,
                                 performs exact string comparison.
        """
        if not isinstance(other, ConfigStanza):
            return False

        if not normalise_whitespace:
            return self.config_lines == other.config_lines

        self_normalised = [self.normalise_line(line) for line in self.config_lines if self.normalise_line(line)]
        other_normalised = [self.normalise_line(line) for line in other.config_lines if self.normalise_line(line)]

        return self_normalised == other_normalised

    @staticmethod
    def normalise_line(line):
        """Conservative normalisation: strip edges and normalise internal whitespace"""
        # Strip leading/trailing whitespace
        stripped = line.strip()
        if not stripped:
            return ''

        # Replace multiple whitespace with single space, but preserve quoted strings
        # This regex preserves quoted strings while normalising other whitespace
        parts = re.split(r'("[^"]*")', stripped)
        normalised_parts = []

        for i, part in enumerate(parts):
            if i % 2 == 0:  # Not inside quotes
                # Normalise whitespace outside quotes
                normalised_parts.append(re.sub(r'\s+', ' ', part))
            else:  # Inside quotes
                # Preserve quoted content exactly
                normalised_parts.append(part)

        return ''.join(normalised_parts)

    def _discover_dependencies(self, collection: 'StanzaCollection') -> List[str]:
        """Override in subclasses to implement specific dependency discovery"""
        return []

    def _discover_dependents(self, collection: 'StanzaCollection') -> List[str]:
        """Find all objects in the collection that depend on this stanza"""
        dependents = []
        for stanza in collection:
            if stanza != self:
                dependencies = stanza.get_dependencies(collection)
                if self.full_path in dependencies:
                    dependents.append(stanza.full_path)
        return dependents

    def get_dependencies(self, collection: Optional['StanzaCollection'] = None,
                         force_rediscover: bool = False) -> List[str]:
        """
        Get dependencies with flexible caching behaviour.

        Args:
            collection: Optional collection to discover dependencies against.
                       Required for initial discovery or when force_rediscover=True.
            force_rediscover: If True, forces rediscovery even if dependencies are cached.
                             If False and dependencies are cached, returns cached result
                             regardless of collection parameter.

        Returns:
            List of dependency full paths

        Raises:
            ValueError: If dependencies haven't been discovered and no collection provided,
                       or if force_rediscover=True but no collection provided.
        """
        if force_rediscover:
            if collection is None:
                raise ValueError(
                    f"Cannot force rediscovery for '{self.full_path}' without a collection parameter."
                )
            # Force rediscovery with collection
            self._dependencies = self._discover_dependencies(collection)
            return self._dependencies

        # If cached, return cache regardless of collection parameter
        if self._dependencies is not None:
            return self._dependencies

        # Not cached - need collection to discover
        if collection is None:
            raise ValueError(
                f"Dependencies for '{self.full_path}' haven't been discovered yet. "
                "Call with a collection parameter first."
            )

        # Discover and cache
        self._dependencies = self._discover_dependencies(collection)
        return self._dependencies

    def get_dependents(self, collection: Optional['StanzaCollection'] = None,
                       force_rediscover: bool = False) -> List[str]:
        """
        Get dependents with flexible caching behaviour.

        Args:
            collection: Optional collection to discover dependents against.
                       Required for initial discovery or when force_rediscover=True.
            force_rediscover: If True, forces rediscovery even if dependents are cached.
                             If False and dependents are cached, returns cached result
                             regardless of collection parameter.

        Returns:
            List of dependent full paths

        Raises:
            ValueError: If dependents haven't been discovered and no collection provided,
                       or if force_rediscover=True but no collection provided.
        """
        if force_rediscover:
            if collection is None:
                raise ValueError(
                    f"Cannot force rediscovery for '{self.full_path}' without a collection parameter."
                )
            # Force rediscovery with collection
            self._dependents = self._discover_dependents(collection)
            return self._dependents

        # If cached, return cache regardless of collection parameter
        if self._dependents is not None:
            return self._dependents

        # Not cached - need collection to discover
        if collection is None:
            raise ValueError(
                f"Dependents for '{self.full_path}' haven't been discovered yet. "
                "Call with a collection parameter first."
            )

        # Discover and cache
        self._dependents = self._discover_dependents(collection)
        return self._dependents

    @property
    def full_path(self) -> str:
        """Complete stanza identifier: prefix + name"""
        return f"{' '.join(self.prefix)} {self.name}"

    def _invalidate_cache(self):
        """Reset parsed config and dependencies/dependents cache"""
        self._parsed_config = None
        self._dependencies = None
        self._dependents = None

    @property
    def parsed_config(self) -> Dict[str, Any]:
        """Get parsed configuration (automatically parses if needed)"""
        if self._parsed_config is None:
            self._parsed_config = self._do_parse()
        return self._parsed_config

    def _do_parse(self) -> Dict[str, Any]:
        """Override this method in subclasses for custom parsing"""
        return self._parse_lines(self.config_lines, 0)[0]

    def get_config_value(self, key: str) -> Any:
        """Convenience method to get parsed config values"""
        return self.parsed_config.get(key)

    def find_and_replace(self,
                         search_pattern: Union[str, re.Pattern],
                         replacement: str,
                         match_type: Literal["word_boundary", "substring", "whole_line"] = "word_boundary",
                         change_id: Optional[str] = None) -> int:
        """Find and replace text in configuration lines, logging changes via the MonitoredList."""
        if change_id is None:
            change_id = str(uuid.uuid4())[:8]

        modifications_made = 0

        # The high-level context is set here, to be shared by all records
        base_context = {
            "change_id": change_id,
            "search_pattern": search_pattern,
            "replacement": replacement,
            "source_operation": 'find_and_replace_method',
            "change_type": 'find_replace',
            "match_type": match_type
        }

        for i, line in enumerate(self.config_lines):
            new_content = None
            match_found = None

            # Original logic to find and determine new_content and match_found
            if isinstance(search_pattern, str):
                leading_spaces = line[:line.index(line.lstrip(' ')[0])] if line.strip() else ""
                if match_type == "word_boundary":
                    words = line.split()
                    if search_pattern in words:
                        new_words = [replacement if word == search_pattern else word for word in words]
                        new_content = leading_spaces + ' '.join(new_words)
                        match_found = search_pattern
                elif match_type == "substring":
                    if search_pattern in line:
                        new_content = line.replace(search_pattern, replacement)
                        match_found = search_pattern
                elif match_type == "whole_line":
                    if line.strip() == search_pattern:
                        new_content = leading_spaces + replacement
                        match_found = search_pattern
            else:  # assuming it's a regex pattern
                match = search_pattern.search(line)
                if match:
                    new_content = search_pattern.sub(replacement, line)
                    match_found = match.group(0)

            # Check if a change was made and perform the assignment
            if new_content is not None and new_content != line:
                # Create the specific context for this single update
                update_context = {**base_context, "match_found": match_found}

                with self.config_lines.with_context(**update_context):
                    self.config_lines[i] = new_content
                    modifications_made += 1

        return modifications_made

    def _parse_lines(self, lines: List[str], start_index: int) -> Tuple[Dict[str, Any], int]:
        """
        Recursively parse configuration lines into nested dictionary.
        """
        result = {}
        i = start_index

        while i < len(lines):
            line = lines[i].strip()

            # Skip empty lines and comments
            if not line or line.startswith('#'):
                i += 1
                continue

            # Check if this line opens a new block
            if line.endswith('{'):
                # Extract the key (everything before the {)
                key = line[:-1].strip()

                # Recursively parse the nested block
                nested_dict, next_index = self._parse_lines(lines, i + 1)
                result[key] = nested_dict
                i = next_index
            elif line == '}':
                # End of current block
                return result, i + 1
            else:
                # Simple key-value pair
                if ' ' in line:
                    # Split on first space - key and value
                    parts = line.split(' ', 1)
                    key = parts[0]
                    value = parts[1] if len(parts) > 1 else ""

                    # Handle multiple values for same key (convert to list)
                    if key in result:
                        if not isinstance(result[key], list):
                            result[key] = [result[key]]
                        result[key].append(value)
                    else:
                        result[key] = value
                else:
                    # Line with no space - just a key
                    result[line] = True

                i += 1

        return result, i

    def _apply_partition_if_missing(self, object_name: str) -> str:
        """Apply current stanza's partition to object name if not already prefixed"""
        if object_name.startswith('/'):
            # Already has partition prefix
            return object_name

        # Extract partition from current stanza's name
        if self.name.startswith('/'):
            partition = self.name.split('/')[1]
            return f"/{partition}/{object_name}"

        # Fallback to no partition
        return object_name

    def get_default_rd(self, collection: 'StanzaCollection') -> str:
        """
        Get the default route domain for the current object.

        Determines the default route domain by:
        1. If this object is a partition, returns its configured default-route-domain
        2. If this object's name starts with '/', extracts the partition name and
           looks up the default-route-domain from that partition
        3. Falls back to '0' if no specific domain is configured

        Args:
            collection: StanzaCollection containing partition objects to resolve against

        Returns:
            Default route domain as a string, defaults to '0'
        """
        # Direct partition lookup
        if self.prefix == ("auth", "partition"):
            return self.parsed_config.get("default-route-domain", '0')

        # Extract partition from object name if it follows /partition/... pattern
        if self.name.startswith('/'):
            partition_name = self.name.split('/')[1]
            partition_obj = collection.resolve_object_by_name(partition_name, ("auth", "partition"))
            if partition_obj:
                return collection[partition_obj].parsed_config.get("default-route-domain", '0')

        return "0"

    @property
    def config_lines(self) -> MonitoredList:
        """Get the config lines as a MonitoredList"""
        return self._config_lines

    @config_lines.setter
    def config_lines(self, value: List[str]):
        """
        Set config lines, converting to MonitoredList and logging the replacement.

        Args:
            value: New list of configuration lines
        """
        # Only log if this is NOT the initial assignment
        if hasattr(self, '_config_lines'):
            # Get the old content for logging
            old_content = list(self._config_lines)

            # Create new MonitoredList with the invalidation callback
            self._config_lines = MonitoredList(
                value,
                change_log=self._changes,
                invalidate_callback=self._invalidate_cache
            )

            # Log the replacement
            change_record = ChangeRecord(
                change_id=str(uuid.uuid4())[:8],
                timestamp=datetime.now(),
                line_index=-1,  # -1 indicates full replacement
                old_content=old_content,
                new_content=list(value),
                search_pattern="N/A",
                replacement="N/A",
                match_found="N/A",
                change_type="total_replacement",
                source_operation="config_lines_assignment"
            )
            self._changes.append(change_record)
            print(
                f"Logged change: {change_record.source_operation} - replaced {len(old_content)} lines with {len(value)} lines")

            # Manually invalidate cache since we bypassed MonitoredList methods
            self._invalidate_cache()
        else:
            # Initial assignment - no logging or cache invalidation needed
            self._config_lines = MonitoredList(
                value,
                change_log=self._changes,
                invalidate_callback=self._invalidate_cache
            )

    def log_addition(self, collection_name: str = "collection", change_id: Optional[str] = None) -> None:
        """
        Log the addition of this stanza to a collection.

        Args:
            collection_name: Name of the collection this stanza is being added to
            change_id: Optional change ID for tracking related operations
        """
        if change_id is None:
            change_id = str(uuid.uuid4())[:8]

        change_record = ChangeRecord(
            change_id=change_id,
            timestamp=datetime.now(),
            line_index=-1,  # -1 indicates collection-level operation
            old_content=None,
            new_content=f"Added to {collection_name}",
            search_pattern="N/A",
            replacement="N/A",
            match_found="N/A",
            change_type="addition",
            source_operation="manual_addition_to_collection"
        )
        self._changes.append(change_record)
        print(f"Logged change: {change_record.source_operation} - {self.full_path} added to {collection_name}")