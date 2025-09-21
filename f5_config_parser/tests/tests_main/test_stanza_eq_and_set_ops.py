import pytest
from f5_config_parser.stanza import ConfigStanza
from f5_config_parser.collection import StanzaCollection


@pytest.fixture
def sample_stanzas():
    """Fixture providing sample stanzas for testing"""
    stanza1 = ConfigStanza(
        prefix=("ltm", "pool"),
        name="app-pool",
        config_lines=["members { 192.168.1.10:80 192.168.1.11:80 }"]
    )

    stanza2 = ConfigStanza(
        prefix=("ltm", "virtual"),
        name="app-vs",
        config_lines=["destination 192.168.1.100:80", "pool app-pool"]
    )

    stanza3 = ConfigStanza(
        prefix=("ltm", "node"),
        name="192.168.1.10",
        config_lines=["address 192.168.1.10"]
    )

    # Same name as stanza1 but different content
    stanza1_different = ConfigStanza(
        prefix=("ltm", "pool"),
        name="app-pool",
        config_lines=["members { 192.168.1.20:80 192.168.1.21:80 }"]
    )

    # Identical to stanza2
    stanza2_identical = ConfigStanza(
        prefix=("ltm", "virtual"),
        name="app-vs",
        config_lines=["destination 192.168.1.100:80", "pool app-pool"]
    )

    return {
        'stanza1': stanza1,
        'stanza2': stanza2,
        'stanza3': stanza3,
        'stanza1_different': stanza1_different,
        'stanza2_identical': stanza2_identical
    }


@pytest.fixture
def sample_collections(sample_stanzas):
    """Fixture providing sample collections"""
    s = sample_stanzas

    collection1 = StanzaCollection([s['stanza1'], s['stanza2'], s['stanza3']])
    collection2 = StanzaCollection([s['stanza1_different'], s['stanza2_identical']])

    return collection1, collection2


class TestStringComparison:
    """Test ConfigStanza comparison with strings"""

    def test_stanza_equals_string_full_path(self, sample_stanzas):
        """Test that stanza equals its full_path string"""
        stanza = sample_stanzas['stanza1']
        assert stanza == "ltm pool app-pool"
        assert stanza != "ltm pool different-pool"

    def test_stanza_equals_stanza_with_content(self, sample_stanzas):
        """Test that stanza comparison includes content when comparing objects"""
        s = sample_stanzas

        # Same name, same content
        assert s['stanza2'] == s['stanza2_identical']

        # Same name, different content
        assert s['stanza1'] != s['stanza1_different']


class TestBasicSetOperations:
    """Test basic set operations between stanzas and strings"""

    def test_string_set_intersection_with_stanza_set(self, sample_stanzas):
        """Test intersection between string names and stanza objects"""
        s = sample_stanzas

        # String set of names
        target_names = {"ltm pool app-pool", "ltm virtual app-vs"}

        # Object set
        stanza_set = {x.full_path for x in [s['stanza1'], s['stanza2'], s['stanza3']]}

        # Intersection should return stanzas that match the names
        intersection = stanza_set & target_names

        assert len(intersection) == 2
        assert s['stanza1'].full_path in intersection
        assert s['stanza2'].full_path in intersection
        assert s['stanza3'].full_path not in intersection

    def test_stanza_set_intersection_with_string_set(self, sample_stanzas):
        """Test intersection from the other direction"""
        s = sample_stanzas

        target_names = {"ltm pool app-pool", "ltm node 192.168.1.10"}
        stanza_set = {x.full_path for x in [s['stanza1'], s['stanza2'], s['stanza3']]}

        # Should work both ways
        intersection1 = stanza_set & target_names
        intersection2 = target_names & stanza_set

        assert intersection1 == intersection2
        assert len(intersection1) == 2
        assert s['stanza1'].full_path in intersection1
        assert s['stanza3'].full_path in intersection1

    def test_set_difference_operations(self, sample_stanzas):
        """Test set difference operations"""
        s = sample_stanzas

        stanza_set = {x.full_path for x in [s['stanza1'], s['stanza2'], s['stanza3']]}
        target_names = {"ltm pool app-pool", "ltm virtual non-existent"}

        # Stanzas not in target names
        not_in_target = stanza_set - target_names
        assert len(not_in_target) == 2  # stanza2 and stanza3
        assert s['stanza2'].full_path in not_in_target
        assert s['stanza3'].full_path in not_in_target

        # Target names not in stanzas (this returns strings)
        names_not_in_stanzas = target_names - stanza_set
        assert names_not_in_stanzas == {"ltm virtual non-existent"}


class TestCollectionSetOperations:
    """Test set operations using collection data"""

    def test_find_stanzas_with_same_name_different_content_manual(self, sample_collections, sample_stanzas):
        """Test finding stanzas with same names but different content using manual set operations"""
        collection1, collection2 = sample_collections
        s = sample_stanzas

        # Manual implementation using set operations
        # Step 1: Find common names
        names1 = {obj.full_path for obj in collection1}
        names2 = {obj.full_path for obj in collection2}
        common_names = names1 & names2

        # Step 2: Get stanzas with common names from collection1
        collection1_common = {obj for obj in collection1 if obj.full_path in common_names}

        # Step 3: Find identical stanzas (same name and content)
        collection2_set = set(collection2)
        identical_stanzas = collection1_common & collection2_set

        # Step 4: Find different content (common names - identical)
        different_content_stanzas = collection1_common - identical_stanzas

        # Should find stanza1 (same name as stanza1_different but different content)
        assert len(different_content_stanzas) == 1
        assert s['stanza1'] in different_content_stanzas

    def test_collection_comparison_using_sets(self, sample_collections, sample_stanzas):
        """Test comprehensive collection comparison using manual set operations"""
        collection1, collection2 = sample_collections
        s = sample_stanzas

        # Get name sets
        names1 = {obj.full_path for obj in collection1}
        names2 = {obj.full_path for obj in collection2}

        # Get object sets
        objects1 = set(collection1)
        objects2 = set(collection2)

        # Find categories
        only_in_collection1_names = names1 - names2
        only_in_collection2_names = names2 - names1
        common_names = names1 & names2

        # Find identical objects (same name and content)
        identical_objects = objects1 & objects2

        # Find objects with common names
        collection1_common = {obj for obj in collection1 if obj.full_path in common_names}
        collection2_common = {obj for obj in collection2 if obj.full_path in common_names}

        # Find different content
        collection1_different = collection1_common - identical_objects
        collection2_different = collection2_common - identical_objects

        # Verify results
        assert only_in_collection1_names == {"ltm node 192.168.1.10"}  # stanza3
        assert len(only_in_collection2_names) == 0  # all names in collection2 exist in collection1

        assert len(identical_objects) == 1  # stanza2 == stanza2_identical
        assert s['stanza2'] in identical_objects

        assert len(collection1_different) == 1  # stanza1
        assert s['stanza1'] in collection1_different

        assert len(collection2_different) == 1  # stanza1_different
        assert s['stanza1_different'] in collection2_different


class TestAdvancedSetOperations:
    """Test advanced set operation scenarios"""

    def test_filter_collection_by_name_set(self, sample_collections):
        """Test filtering collection using set of names"""
        collection1, _ = sample_collections

        # Filter by specific names
        target_names = {"ltm pool app-pool", "ltm node 192.168.1.10"}

        # Convert to sets for intersection
        stanza_set = set(collection1)
        filtered_stanzas = {x.full_path for x in stanza_set} & target_names
        filtered_collection = StanzaCollection([collection1[x] for x in filtered_stanzas])

        assert len(filtered_collection) == 2
        full_paths = {s.full_path for s in filtered_collection}
        assert full_paths == target_names

    def test_three_way_name_comparison(self, sample_stanzas):
        """Test three-way comparison using set operations"""
        s = sample_stanzas

        # Three different sets
        set1 = {s['stanza1'], s['stanza2']}
        set2 = {s['stanza1_different'], s['stanza3']}  # Different content for stanza1
        names_of_interest = {"ltm pool app-pool", "ltm virtual app-vs", "ltm node 192.168.1.10"}

        # Find what's common across all three
        set1_names = {obj.full_path for obj in set1}
        set2_names = {obj.full_path for obj in set2}

        common_to_all = set1_names & set2_names & names_of_interest
        assert common_to_all == {"ltm pool app-pool"}

        # Find objects in set1 that match names of interest
        set1_matching = {x.full_path for x in set1} & names_of_interest
        assert len(set1_matching) == 2

        # Find objects in set2 that match names of interest
        set2_matching = {x.full_path for x in set2} & names_of_interest
        assert len(set2_matching) == 2

    def test_content_vs_name_based_operations(self, sample_stanzas):
        """Test the difference between name-based and content-based set operations"""
        s = sample_stanzas

        # Two sets with same names but different content
        set1 = {s['stanza1'], s['stanza2']}
        set2 = {s['stanza1_different'], s['stanza2_identical']}

        # Name-based intersection (using string comparison)
        names1 = {obj.full_path for obj in set1}
        names2 = {obj.full_path for obj in set2}
        common_names = names1 & names2
        assert len(common_names) == 2  # Both pools and virtuals have same names

        # Content-based intersection (using object comparison)
        identical_objects = set1 & set2
        assert len(identical_objects) == 1  # Only stanza2 and stanza2_identical are identical
        assert s['stanza2'] in identical_objects

        # Objects with same names but different content
        set1_with_common_names = {obj for obj in set1 if obj.full_path in common_names}
        different_content_objects = set1_with_common_names - identical_objects
        assert len(different_content_objects) == 1
        assert s['stanza1'] in different_content_objects


class TestEdgeCases:
    """Test edge cases and error conditions"""

    def test_empty_set_operations(self):
        """Test set operations with empty sets"""
        empty_stanza_set = set()
        empty_name_set = set()
        name_set = {"ltm pool test"}

        assert empty_stanza_set & name_set == set()
        assert empty_name_set & empty_stanza_set == set()

    def test_no_common_names(self, sample_stanzas):
        """Test when collections have no common names"""
        s = sample_stanzas

        set1 = {s['stanza1'], s['stanza2']}
        completely_different_names = {"ltm pool different", "ltm virtual other"}

        intersection = set1 & completely_different_names
        assert len(intersection) == 0

    def test_mixed_type_operations(self, sample_stanzas):
        """Test operations with mixed types"""
        s = sample_stanzas

        # Mix of strings and objects
        mixed_set = {"ltm pool app-pool", s['stanza2'], "ltm node other"}
        stanza_set = {x.full_path for x in [s['stanza1'], s['stanza3']]}

        # Should still work
        intersection = mixed_set & stanza_set
        assert s['stanza1'].full_path in intersection  # Matches the string "ltm pool app-pool"

    def test_hash_collision_handling(self, sample_stanzas):
        """Test that objects with same hash but different equality work correctly"""
        s = sample_stanzas

        # These have the same full_path (and thus same hash) but different content
        same_name_set = {s['stanza1'], s['stanza1_different']}

        # Set should contain both because they're not equal (different content)
        assert len(same_name_set) == 2

        # When intersecting with string, both objects match the string "ltm pool app-pool"
        # but the intersection will only contain one of them (whichever set operations finds first)
        string_set = {"ltm pool app-pool"}
        intersection = {x.full_path for x in same_name_set} & string_set
        assert len(intersection) == 1  # Only one object will be in the intersection

        # Verify that the object in the intersection does match the string
        intersection_obj = next(iter(intersection))
        assert intersection_obj == "ltm pool app-pool"

        # Both original objects should individually match the string
        assert s['stanza1'] == "ltm pool app-pool"
        assert s['stanza1_different'] == "ltm pool app-pool"


@pytest.mark.parametrize("operation", [
    "intersection",
    "difference",
    "symmetric_difference",
    "union"
])
def test_all_set_operations_work(sample_stanzas, operation):
    """Parameterised test ensuring all set operations work with mixed types"""
    s = sample_stanzas

    stanza_set = {s['stanza1'], s['stanza2']}
    name_set = {"ltm pool app-pool", "ltm node 192.168.1.10"}

    if operation == "intersection":
        result = stanza_set & name_set
        assert isinstance(result, set)
    elif operation == "difference":
        result = stanza_set - name_set
        assert isinstance(result, set)
    elif operation == "symmetric_difference":
        result = stanza_set ^ name_set
        assert isinstance(result, set)
    elif operation == "union":
        result = stanza_set | name_set
        assert isinstance(result, set)


def test_real_world_workflow(sample_collections, sample_stanzas):
    """Test a realistic workflow using set operations"""
    collection1, collection2 = sample_collections
    s = sample_stanzas

    # Step 1: Define target configurations
    critical_configs = {"ltm pool app-pool", "ltm virtual app-vs"}

    # Step 2: Find what exists in both collections (by name)
    collection1_names = {obj.full_path for obj in collection1}
    collection2_names = {obj.full_path for obj in collection2}
    common_names = collection1_names & collection2_names & critical_configs

    # Step 3: Get actual objects with those names
    collection1_critical = {obj for obj in collection1 if obj.full_path in common_names}
    collection2_critical = {obj for obj in collection2 if obj.full_path in common_names}

    # Step 4: Find identical configurations
    identical_critical = collection1_critical & collection2_critical

    # Step 5: Find configurations that need attention (same name, different content)
    needs_attention = collection1_critical - identical_critical

    # Verify results
    assert len(common_names) == 2  # Both critical configs exist in both collections
    assert len(identical_critical) == 1  # Only app-vs is identical
    assert len(needs_attention) == 1  # app-pool needs attention
    assert s['stanza1'] in needs_attention  # This is the problematic config