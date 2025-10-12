from typing import List, Optional, Tuple, Union, Iterator, Dict, Literal, Set
import re
from collections import Counter
from f5_config_parser.caching import DependencyCache
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
        # Check for duplicate full_path attributes in the initial stanzas
        full_paths = [stanza.full_path for stanza in stanzas]
        duplicates = [path for path, count in Counter(full_paths).items() if count > 1]

        if duplicates:
            raise DuplicateStanzaError(
                f"Cannot initialise StanzaCollection - duplicate full_path(s) found: {sorted(duplicates)}")

        self.stanzas = stanzas
        self.config_str = config_str
        self._cache = DependencyCache(config_str) if config_str else None

    @classmethod
    def from_config(cls,
                    config_text: str,
                    initialise: bool = True,  # Keep True as default for main entry point
                    validate: bool = True) -> 'StanzaCollection':
        """Create collection from config text with optional full initialisation.

        This is the primary entry point for creating a StanzaCollection.

        Args:
            config_text: Raw F5 configuration text
            initialise: If True, run full initialisation (ip_rd + dependencies)
            validate: If True, validate the parsed configuration
        """
        if not config_text.strip():
            raise ValueError("Empty config string provided")

        parsed_stanzas = StanzaFactory.parse_stanzas(config_text)
        collection = cls(parsed_stanzas, config_text)

        if validate:
            validate_config(config_text, collection)

        if initialise:
            collection.initialise_ip_to_rd()
            collection.initialise_dependencies()

        return collection

    def initialise_ip_to_rd(self) -> None:
        """Initialise IP and route domain attributes for applicable stanzas.

        Processes stanzas that have IP configuration to extract and set their
        ip_rd attribute as a tuple of (address, route_domain).
        """
        for stanza in self.stanzas:
            # Initialise IP/RD attributes for SelfIP stanzas
            if hasattr(stanza, '_parse_ips_to_ip_rd'):
                stanza._parse_ips_to_ip_rd(self)

    def initialise_dependencies(self, ignore_cache: bool = False) -> None:
        """Discover and set dependencies for all stanzas in the collection.

        Uses collection context to resolve object references and populate
        the _dependencies attribute for each stanza.

        Args:
            ignore_cache: If True, bypass cache loading and recalculate all dependencies
        """
        # Get paths for stanzas we need to process
        stanza_paths = {stanza.full_path for stanza in self.stanzas}

        # Check cache coverage unless ignoring cache
        use_cache = False
        cached_dependencies = None

        if not ignore_cache and self._cache and stanza_paths:
            if self._cache.check_coverage(stanza_paths, 'dependencies'):
                cached_dependencies = self._cache.load('dependencies')
                if cached_dependencies is not None:
                    use_cache = True

        if use_cache:
            # Apply cached dependencies to stanzas
            for stanza in self.stanzas:
                if stanza.full_path in cached_dependencies:
                    stanza._dependencies = cached_dependencies[stanza.full_path]
            return

        # Cache miss, incomplete coverage, or ignoring cache - calculate dependencies
        for stanza in self.stanzas:
            # Discover dependencies for all stanzas
            dependencies = stanza.get_dependencies(self, force_rediscover=True)
            stanza._dependencies = dependencies

    def save_dependency_cache(self) -> None:
        """Save current dependency state to cache.

        Saves the current _dependencies attribute of all stanzas to the cache file.
        Only saves if cache is available and stanzas have dependencies initialised.
        """
        if not self._cache:
            return

        # Collect current dependency state from all stanzas
        dependencies_data = {}

        for stanza in self.stanzas:
            if hasattr(stanza, '_dependencies') and stanza._dependencies is not None:
                dependencies_data[stanza.full_path] = stanza._dependencies

        # Only save if we have dependency data
        if dependencies_data:
            self._cache.save(dependencies_data, 'dependencies')

    def __len__(self) -> int:
        return len(self.stanzas)

    def __bool__(self) -> bool:
        return bool(self.stanzas)

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
        other_paths = [stanza.full_path for stanza in other_stanzas]
        internal_duplicates = [path for path, count in Counter(other_paths).items() if count > 1]

        if internal_duplicates:
            raise DuplicateStanzaError(
                f"Cannot add stanzas - duplicates found within the argument: {sorted(internal_duplicates)}.")

        # Check for duplicates between collections
        existing_paths = {stanza.full_path for stanza in self.stanzas}
        other_paths_set = set(other_paths)
        duplicates_between = existing_paths & other_paths_set

        if duplicates_between:
            raise DuplicateStanzaError(
                f"Cannot add stanzas with duplicate full_path(s): {sorted(duplicates_between)}. "
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
        other_paths = [stanza.full_path for stanza in other_stanzas]
        internal_duplicates = [path for path, count in Counter(other_paths).items() if count > 1]

        if internal_duplicates:
            raise DuplicateStanzaError(
                f"Cannot add stanzas - duplicates found within the argument: {sorted(internal_duplicates)}.")

        # Check for duplicates between collections
        existing_paths = {stanza.full_path for stanza in self.stanzas}
        other_paths_set = set(other_paths)
        duplicates_between = existing_paths & other_paths_set

        if duplicates_between:
            raise DuplicateStanzaError(
                f"Cannot add stanzas with duplicate full_path(s): {sorted(duplicates_between)}. "
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

    def sort(self) -> 'StanzaCollection':
        """Sort stanzas with ltm virtual taking precedence, then alphabetically by full_path.

        Returns:
            Self for method chaining
        """
        self.stanzas.sort()
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
            if isinstance(expected_value, re.Pattern):
                if actual_value is None or not expected_value.search(str(actual_value)):
                    return False
            else:
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
                            relation_type: Literal[
                                'dependencies', 'dependents'] = 'dependencies') -> 'StanzaCollection':
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