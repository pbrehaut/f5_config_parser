from typing import List, Optional, Tuple, Union, Iterator, Dict
import re
import json
import hashlib
import os
from f5_config_parser.stanza import ConfigStanza
from f5_config_parser.factory import StanzaFactory
from f5_config_parser.validate_scf_parsing import validate_config
from f5_config_parser.f5_constants import F5_PROFILES, F5_MONITORS


class DuplicateStanzaError(Exception):
    """Raised when attempting to add a stanza that already exists in the collection."""
    pass


class StanzaCollection:
    """Collection of stanzas with bulk operations and analysis methods"""

    def __init__(self, stanzas: List[ConfigStanza], config_str: Optional[str] = None):
        """Basic constructor - stores stanzas and optional config string"""
        self.stanzas = stanzas
        self.config_str = config_str
        self._config_hash = None
        if config_str:
            self._config_hash = self._calculate_config_hash(config_str)

    def _calculate_config_hash(self, config_str: str) -> str:
        """Calculate SHA-256 hash of the config string."""
        return hashlib.sha256(config_str.encode('utf-8')).hexdigest()

    def _get_cache_filename(self, cache_type: str) -> str:
        """Generate cache filename based on config hash and cache type."""
        if not self._config_hash:
            raise ValueError("No config hash available for caching")
        return f"dependency_cache_{cache_type}_{self._config_hash}.json"

    def _save_dependencies_cache(self, dependencies_data: Dict[str, List[str]], cache_type: str) -> None:
        """Save dependency data to cache file."""
        cache_filename = self._get_cache_filename(cache_type)
        try:
            with open(cache_filename, 'w') as f:
                json.dump(dependencies_data, f, indent=2)
            print(f"Saved {cache_type} cache to {cache_filename}")
        except Exception as e:
            print(f"Warning: Failed to save {cache_type} cache: {e}")

    @classmethod
    def from_config(cls,
                    config_text: str,
                    initialise_ip_rd: bool = True,
                    initialise_dependencies: bool = True,
                    initialise_irule_dependencies: bool = False) -> 'StanzaCollection':
        """Create collection from config text with full initialisation options"""
        if not config_text.strip():
            raise ValueError("Empty config string provided")

        parsed_stanzas = StanzaFactory.parse_stanzas(config_text)
        collection = cls(parsed_stanzas, config_text)

        # Validate parsed config
        validate_config(config_text, collection)

        if initialise_ip_rd:
            collection._initialise_ip_to_rd()

        if initialise_dependencies:
            collection._initialise_dependencies()

        if initialise_irule_dependencies:
            collection._initialise_irule_dependencies()

        return collection

    @classmethod
    def from_stanzas(cls,
                     stanzas: List[ConfigStanza],
                     initialise_ip_rd: bool = False,
                     initialise_dependencies: bool = False,
                     initialise_irule_dependencies: bool = False) -> 'StanzaCollection':
        """Create collection from existing stanzas with optional initialisation"""
        collection = cls(stanzas)

        if initialise_ip_rd:
            collection._initialise_ip_to_rd()

        if initialise_dependencies:
            collection._initialise_dependencies()

        if initialise_irule_dependencies:
            collection._initialise_irule_dependencies()

        return collection

    def _initialise_ip_to_rd(self) -> None:
        """Initialise IP and route domain attributes for applicable stanzas.

        Processes stanzas that have IP configuration to extract and set their
        ip_rd attribute as a tuple of (address, route_domain).
        """
        for stanza in self.stanzas:
            # Initialise IP/RD attributes for SelfIP stanzas
            if hasattr(stanza, '_parse_ips_to_ip_rd'):
                stanza._parse_ips_to_ip_rd(self)

    def _load_dependencies_cache(self, cache_type: str) -> Optional[Dict[str, List[str]]]:
        """Load dependency data from cache file if it exists and matches current config hash."""
        if not self._config_hash:
            return None

        try:
            cache_filename = self._get_cache_filename(cache_type)
            with open(cache_filename, 'r') as f:
                dependencies_data = json.load(f)
            print(f"Loaded {cache_type} cache from {cache_filename}")
            return dependencies_data
        except (FileNotFoundError, json.JSONDecodeError, Exception) as e:
            return None

    def _initialise_dependencies(self) -> None:
        """Discover and set dependencies for all non-iRule and non-data-group stanzas in the collection.

        Uses collection context to resolve object references and populate
        the _dependencies attribute for each stanza, excluding iRule and data-group stanzas.
        """
        # Try to load from cache first
        cached_dependencies = self._load_dependencies_cache('standard')

        if cached_dependencies is not None:
            # Apply cached dependencies to stanzas
            for stanza in self.stanzas:
                if stanza.prefix[:2] == ('ltm', 'rule') or stanza.prefix[:2] == ('ltm', 'data-group'):
                    continue
                if stanza.full_path in cached_dependencies:
                    stanza._dependencies = cached_dependencies[stanza.full_path]
            return

        # Cache miss - calculate dependencies normally
        dependencies_data = {}

        for stanza in self.stanzas:
            # Skip iRule and data-group stanzas - they have their own initialisation method
            if stanza.prefix[:2] == ('ltm', 'rule') or stanza.prefix[:2] == ('ltm', 'data-group'):
                continue
            # Discover dependencies for all other stanzas
            dependencies = stanza.get_dependencies(self)
            dependencies_data[stanza.full_path] = dependencies

        # Save dependencies to cache if we have a config hash
        if self._config_hash:
            self._save_dependencies_cache(dependencies_data, 'standard')

    def _initialise_irule_dependencies(self) -> None:
        """Discover and set dependencies for iRule and data-group stanzas in the collection.

        Uses collection context to resolve object references and populate
        the _dependencies attribute for iRule and data-group stanzas only.
        """
        # Try to load from cache first
        cached_dependencies = self._load_dependencies_cache('irule')

        if cached_dependencies is not None:
            # Apply cached dependencies to stanzas
            for stanza in self.stanzas:
                if stanza.prefix[:2] == ('ltm', 'rule') or stanza.prefix[:2] == ('ltm', 'data-group'):
                    if stanza.full_path in cached_dependencies:
                        stanza._dependencies = cached_dependencies[stanza.full_path]
            return

        # Cache miss - calculate dependencies normally
        dependencies_data = {}

        for stanza in self.stanzas:
            # Only process iRule and data-group stanzas
            if stanza.prefix[:2] == ('ltm', 'rule') or stanza.prefix[:2] == ('ltm', 'data-group'):
                dependencies = stanza.get_dependencies(self)
                dependencies_data[stanza.full_path] = dependencies

        # Save dependencies to cache if we have a config hash
        if self._config_hash:
            self._save_dependencies_cache(dependencies_data, 'irule')

    def __len__(self) -> int:
        return len(self.stanzas)

    def __str__(self) -> str:
        return ''.join([str(stanza) for stanza in self.stanzas])

    def __iter__(self) -> Iterator[ConfigStanza]:
        return iter(self.stanzas)

    def __getitem__(self, key: Union[int, str]) -> ConfigStanza:
        if isinstance(key, int):
            return self.stanzas[key]
        else:  # string - treat as full_path
            for stanza in self.stanzas:
                if stanza.full_path == key:
                    return stanza
            raise KeyError(f"No stanza found with full_path: {key}")

    def __contains__(self, item: Union[str, ConfigStanza]) -> bool:
        """Check if item is in collection by full_path or object identity."""
        if isinstance(item, str):
            # Check by full_path
            return any(stanza.full_path == item for stanza in self.stanzas)
        elif isinstance(item, ConfigStanza):
            # Check by object identity first, then by full_path as fallback
            return item in self.stanzas or any(stanza.full_path == item.full_path for stanza in self.stanzas)
        else:
            return False

    def __add__(self, other: Union[ConfigStanza, List[ConfigStanza], 'StanzaCollection']) -> 'StanzaCollection':
        """Return new collection with items from both collections."""
        new_stanzas = self.stanzas.copy()
        other_stanzas = self._normalise_items(other)

        # Check for duplicates within the argument being added
        other_set = set(other_stanzas)
        if len(other_set) != len(other_stanzas):
            # Find the duplicates within the argument
            seen = set()
            internal_duplicates = []
            for stanza in other_stanzas:
                if stanza.full_path in seen:
                    internal_duplicates.append(stanza.full_path)
                seen.add(stanza.full_path)

            raise DuplicateStanzaError(
                f"Cannot add stanzas - duplicates found within the argument: {sorted(internal_duplicates)}.")

        # Use set operations to detect duplicates between collections
        existing_set = set(self.stanzas)
        duplicates_between = existing_set & other_set

        if duplicates_between:
            duplicate_paths = {stanza.full_path for stanza in duplicates_between}
            raise DuplicateStanzaError(
                f"Cannot add stanzas with duplicate full_path(s): {sorted(duplicate_paths)}. "
                f"If you want to replace objects with the same name, overwrite the config_lines "
                f"list attribute in the existing object instead."
            )

        # Add all stanzas since no duplicates found
        new_stanzas.extend(other_stanzas)

        # Log addition for each new stanza
        for stanza in other_stanzas:
            stanza.log_addition("StanzaCollection")

        return StanzaCollection(new_stanzas)

    def __iadd__(self, other: Union[ConfigStanza, List[ConfigStanza], 'StanzaCollection']) -> 'StanzaCollection':
        """Add items to this collection in-place."""
        other_stanzas = self._normalise_items(other)

        # Check for duplicates within the argument being added
        other_set = set(other_stanzas)
        if len(other_set) != len(other_stanzas):
            # Find the duplicates within the argument
            seen = set()
            internal_duplicates = []
            for stanza in other_stanzas:
                if stanza.full_path in seen:
                    internal_duplicates.append(stanza.full_path)
                seen.add(stanza.full_path)

            raise DuplicateStanzaError(
                f"Cannot add stanzas - duplicates found within the argument: {sorted(internal_duplicates)}.")

        # Use set operations to detect duplicates between collections
        existing_set = set(self.stanzas)
        duplicates_between = existing_set & other_set

        if duplicates_between:
            duplicate_paths = {stanza.full_path for stanza in duplicates_between}
            raise DuplicateStanzaError(
                f"Cannot add stanzas with duplicate full_path(s): {sorted(duplicate_paths)}. "
                f"If you want to replace objects with the same name, overwrite the config_lines "
                f"list attribute in the existing object instead."
            )

        # Add all stanzas since no duplicates found
        self.stanzas.extend(other_stanzas)

        # Log addition for each new stanza
        for stanza in other_stanzas:
            stanza.log_addition("StanzaCollection")

        return self

    def __sub__(self, other: Union[ConfigStanza, List[ConfigStanza], 'StanzaCollection']) -> 'StanzaCollection':
        """Return new collection with specified items removed."""
        other_stanzas = self._normalise_items(other)
        paths_to_remove = {stanza.full_path for stanza in other_stanzas}

        new_stanzas = [stanza for stanza in self.stanzas
                       if stanza.full_path not in paths_to_remove]

        return StanzaCollection(new_stanzas)

    def __isub__(self, other: Union[ConfigStanza, List[ConfigStanza], 'StanzaCollection']) -> 'StanzaCollection':
        """Remove specified items from this collection in-place."""
        other_stanzas = self._normalise_items(other)
        paths_to_remove = {stanza.full_path for stanza in other_stanzas}

        self.stanzas = [stanza for stanza in self.stanzas
                        if stanza.full_path not in paths_to_remove]

        return self

    def _normalise_items(self, items: Union[ConfigStanza, List[ConfigStanza], 'StanzaCollection']) -> List[
        ConfigStanza]:
        """Convert supported input types to list of ConfigStanza objects."""
        if isinstance(items, ConfigStanza):
            # Single ConfigStanza object
            return [items]

        elif isinstance(items, StanzaCollection):
            # Another StanzaCollection
            return items.stanzas

        elif isinstance(items, list):
            # List of ConfigStanza objects
            for item in items:
                if not isinstance(item, ConfigStanza):
                    raise TypeError(f"All items in list must be ConfigStanza objects, got {type(item)}")
            return items

        else:
            raise TypeError(f"Unsupported type for collection operation: {type(items)}. "
                            f"Expected ConfigStanza, List[ConfigStanza], or StanzaCollection.")

    def add(self, stanza: ConfigStanza) -> None:
        """Add a single stanza to the collection.

        Args:
            stanza: The ConfigStanza to add

        Raises:
            DuplicateStanzaError: If a stanza with the same full_path already exists
        """
        if stanza.full_path in self:
            raise DuplicateStanzaError(
                f"Cannot add stanza with duplicate full_path: {stanza.full_path}. "
                f"If you want to replace objects with the same name, overwrite the config_lines "
                f"list attribute in the existing object instead."
            )
        self.stanzas.append(stanza)

    def filter(self,
               prefix: Optional[Tuple[str, ...]] = None,
               name: Optional[Union[str, re.Pattern]] = None,
               content: Optional[Union[str, re.Pattern]] = None,
               **parsed_config_filters) -> 'StanzaCollection':
        """Filter this collection to create a subset."""
        filtered_stanzas = self.stanzas

        if prefix is not None:
            filtered_stanzas = [s for s in filtered_stanzas if self._prefix_matches(s.prefix, prefix)]

        if name is not None:
            if isinstance(name, str):
                filtered_stanzas = [s for s in filtered_stanzas if s.name == name]
            else:  # regex pattern
                filtered_stanzas = [s for s in filtered_stanzas if name.search(s.name)]

        if content is not None:
            filtered_stanzas = [s for s in filtered_stanzas
                                if self._content_matches(s, content)]

        if parsed_config_filters:
            filtered_stanzas = [s for s in filtered_stanzas
                                if self._parsed_config_matches(s, parsed_config_filters)]

        return StanzaCollection(filtered_stanzas)

    def _prefix_matches(self, stanza_prefix: Tuple[str, ...], search_prefix: Tuple[str, ...]) -> bool:
        """Check if stanza_prefix starts with search_prefix."""
        if len(search_prefix) > len(stanza_prefix):
            return False
        return stanza_prefix[:len(search_prefix)] == search_prefix

    def _content_matches(self, stanza: ConfigStanza, content_filter: Union[str, re.Pattern]) -> bool:
        """Check if stanza content matches the filter."""
        content_text = '\n'.join(stanza.config_lines)
        if isinstance(content_filter, str):
            return content_filter in content_text
        return content_filter.search(content_text) is not None

    def _parsed_config_matches(self, stanza: ConfigStanza, parsed_config_filters: Dict) -> bool:
        """Check if stanza matches all parsed config filters."""
        for key, expected_value in parsed_config_filters.items():
            actual_value = stanza.parsed_config.get(key)
            if str(actual_value) != str(expected_value):
                return False
        return True

    def resolve_object_by_name(self, object_name: str, scope_prefix: Tuple[str, ...]):
        """
        Resolve an object name within a specific scope (e.g., all ltm profiles).

        Args:
            object_name: The name to resolve (e.g., "my-ssl-profile")
            scope_prefix: The scope to search within (e.g., ("ltm", "profile"))

        Returns:
            Full path of the matching object, or None if no matches found

        Raises:
            ValueError: If multiple matches found
        """
        # If looking for a profile that is one of the F5 default profiles then skip it
        if scope_prefix[:2] == ('ltm', 'profile') and object_name in F5_PROFILES:
            # print(f"Skipping lookup for {object_name} in {scope_prefix}")
            return None

        # If looking for a monitor that is one of the F5 default profiles then skip it
        if scope_prefix[:2] == ('ltm', 'monitor') and object_name in F5_MONITORS:
            # print(f"Skipping lookup for {object_name} in {scope_prefix}")
            return None

        # Find all objects in the scope
        matches = self.filter(prefix=scope_prefix, name=object_name)

        if len(matches) > 1:
            match_paths = [match.full_path for match in matches]
            raise ValueError(
                f"Multiple objects named '{object_name}' found in scope '{' '.join(scope_prefix)}': {match_paths}")

        if len(matches) == 1:
            return matches[0].full_path

        # Log error when no matches found
        print(f"Error: No object named '{object_name}' found in scope '{' '.join(scope_prefix)}'")
        return None

    def get_related_stanzas(self, initial_stanzas: List[ConfigStanza],
                            relation_type: str = 'dependencies') -> 'StanzaCollection':
        """
        Recursively discover all stanzas related to the initial set through dependencies or dependents.

        This method performs a depth-first traversal of the relationship graph starting
        from the provided stanzas. It collects all related stanzas based on the specified
        relation type, returning a new collection containing all related stanzas.

        Args:
            initial_stanzas: List of stanzas to start relationship discovery from
            relation_type: Type of relationship to follow - 'dependencies' or 'dependents'

        Returns:
            New StanzaCollection containing initial stanzas and all their related stanzas

        Raises:
            ValueError: If relation_type is not 'dependencies' or 'dependents'

        Example:
            # Get all stanzas that a virtual server depends on
            vs_stanzas = collection.filter(prefix=("ltm", "virtual"), name="my-vs")
            dependencies = collection.get_related_stanzas(vs_stanzas.stanzas, 'dependencies')

            # Get all stanzas that depend on a pool
            pool_stanzas = collection.filter(prefix=("ltm", "pool"), name="my-pool")
            dependents = collection.get_related_stanzas(pool_stanzas.stanzas, 'dependents')
        """
        if relation_type not in ('dependencies', 'dependents'):
            raise ValueError("relation_type must be 'dependencies' or 'dependents'")

        # Select the appropriate method to call
        get_relations_method = 'get_dependencies' if relation_type == 'dependencies' else 'get_dependents'

        visited = set()  # Track processed stanzas to prevent infinite loops
        result_stanzas = []  # Accumulate all discovered stanzas

        def collect_recursive(stanza: ConfigStanza):
            """Recursively collect a stanza and all its related stanzas"""
            # Skip if we've already processed this stanza
            if stanza.full_path in visited:
                return

            # Mark as visited and add to results
            visited.add(stanza.full_path)
            result_stanzas.append(stanza)

            # Get all related stanzas and recursively process them
            relations_method = getattr(stanza, get_relations_method)
            for relation_path in relations_method(self):
                relation_stanza = self[relation_path]
                if relation_stanza:  # Ignore missing relations as requested
                    collect_recursive(relation_stanza)

        # Start recursive discovery from each initial stanza
        for stanza in initial_stanzas:
            collect_recursive(stanza)

        # Return new collection with all discovered stanzas
        return StanzaCollection(result_stanzas)