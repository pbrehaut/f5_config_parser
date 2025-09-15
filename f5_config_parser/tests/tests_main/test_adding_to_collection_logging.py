import pytest
from unittest.mock import patch
from f5_config_parser.stanza import ConfigStanza
from f5_config_parser.collection import StanzaCollection, DuplicateStanzaError


@pytest.fixture
def test_stanzas():
    """Fixture providing test stanzas"""
    stanza1 = ConfigStanza(
        prefix=("ltm", "pool"),
        name="test-pool-1",
        config_lines=["members { 192.168.1.10:80 192.168.1.11:80 }"]
    )

    stanza2 = ConfigStanza(
        prefix=("ltm", "virtual"),
        name="test-vs-1",
        config_lines=["destination 192.168.1.100:80", "pool test-pool-1"]
    )

    stanza3 = ConfigStanza(
        prefix=("ltm", "node"),
        name="192.168.1.10",
        config_lines=["address 192.168.1.10"]
    )

    return stanza1, stanza2, stanza3


@pytest.fixture
def collection(test_stanzas):
    """Fixture providing collection with initial stanza"""
    stanza1, _, _ = test_stanzas
    return StanzaCollection([stanza1])


def test_log_addition_method_direct_call(test_stanzas):
    """Test calling log_addition method directly"""
    _, stanza2, _ = test_stanzas

    # Clear any existing changes
    stanza2._changes.clear()

    # Call log_addition directly
    stanza2.log_addition("test_collection", "test_change_001")

    # Verify change was logged
    assert len(stanza2._changes) == 1
    change = stanza2._changes[0]

    assert change.change_id == "test_change_001"
    assert change.line_index == -1
    assert change.old_content is None
    assert change.new_content == "Added to test_collection"
    assert change.change_type == "addition"
    assert change.source_operation == "manual_addition_to_collection"


def test_log_addition_method_auto_change_id(test_stanzas):
    """Test log_addition with auto-generated change ID"""
    _, stanza2, _ = test_stanzas

    # Clear any existing changes
    stanza2._changes.clear()

    # Call log_addition without change_id
    stanza2.log_addition("another_collection")

    # Verify change was logged with auto-generated ID
    assert len(stanza2._changes) == 1
    change = stanza2._changes[0]

    assert change.change_id is not None
    assert len(change.change_id) == 8  # UUID4 first 8 chars
    assert change.new_content == "Added to another_collection"


@patch('builtins.print')
def test_iadd_single_stanza_logging(mock_print, collection, test_stanzas):
    """Test logging when adding single stanza with += operator"""
    _, stanza2, _ = test_stanzas

    # Clear existing changes
    stanza2._changes.clear()

    # Add stanza using +=
    collection += stanza2

    # Verify stanza was added
    assert stanza2 in collection.stanzas

    # Verify logging occurred
    assert len(stanza2._changes) == 1
    change = stanza2._changes[0]
    assert change.change_type == "addition"
    assert change.source_operation == "manual_addition_to_collection"
    assert change.new_content == "Added to StanzaCollection"

    # Verify print was called
    mock_print.assert_called()


@patch('builtins.print')
def test_iadd_multiple_stanzas_logging(mock_print, collection, test_stanzas):
    """Test logging when adding multiple stanzas with += operator"""
    _, stanza2, stanza3 = test_stanzas

    # Clear existing changes
    stanza2._changes.clear()
    stanza3._changes.clear()

    # Add multiple stanzas using +=
    collection += [stanza2, stanza3]

    # Verify both stanzas were added
    assert stanza2 in collection.stanzas
    assert stanza3 in collection.stanzas

    # Verify logging occurred for both
    assert len(stanza2._changes) == 1
    assert len(stanza3._changes) == 1

    # Check change details for stanza2
    change2 = stanza2._changes[0]
    assert change2.change_type == "addition"
    assert change2.new_content == "Added to StanzaCollection"

    # Check change details for stanza3
    change3 = stanza3._changes[0]
    assert change3.change_type == "addition"
    assert change3.new_content == "Added to StanzaCollection"


@patch('builtins.print')
def test_add_operator_logging(mock_print, collection, test_stanzas):
    """Test logging when using + operator to create new collection"""
    _, stanza2, _ = test_stanzas

    # Clear existing changes
    stanza2._changes.clear()

    # Create new collection using +
    new_collection = collection + stanza2

    # Verify new collection was created
    assert new_collection is not collection
    assert len(new_collection) == 2

    # Verify logging occurred
    assert len(stanza2._changes) == 1
    change = stanza2._changes[0]
    assert change.change_type == "addition"
    assert change.new_content == "Added to StanzaCollection"


@patch('builtins.print')
def test_add_collection_to_collection_logging(mock_print, collection, test_stanzas):
    """Test logging when adding one collection to another"""
    _, stanza2, stanza3 = test_stanzas

    # Create second collection
    collection2 = StanzaCollection([stanza2, stanza3])

    # Clear existing changes
    stanza2._changes.clear()
    stanza3._changes.clear()

    # Add collection2 to collection using +=
    collection += collection2

    # Verify both stanzas were added and logged
    assert len(stanza2._changes) == 1
    assert len(stanza3._changes) == 1


def test_duplicate_stanza_no_logging_on_error(collection):
    """Test that no logging occurs when duplicate stanza addition fails"""
    # Create duplicate stanza with same full_path as existing
    duplicate_stanza = ConfigStanza(
        prefix=("ltm", "pool"),
        name="test-pool-1",  # Same name as existing stanza
        config_lines=["members { 192.168.1.10:80 192.168.1.11:80 }"]
    )

    # Clear changes
    duplicate_stanza._changes.clear()

    # Attempt to add duplicate - should raise error
    with pytest.raises(DuplicateStanzaError):
        collection += duplicate_stanza

    # Verify no logging occurred due to error
    assert len(duplicate_stanza._changes) == 0


@patch('builtins.print')
def test_add_method_logging(mock_print, collection, test_stanzas):
    """Test logging when using the add() method"""
    _, stanza2, _ = test_stanzas

    # Clear existing changes
    stanza2._changes.clear()

    # Add stanza
    collection += [stanza2]

    assert len(stanza2._changes) == 1


def test_logging_preserves_existing_changes(collection, test_stanzas):
    """Test that logging addition preserves existing change history"""
    _, stanza2, _ = test_stanzas

    # Add some existing changes to stanza2
    existing_change_count = len(stanza2._changes)

    # Perform a find_and_replace to create a change
    stanza2.find_and_replace("test", "replaced", match_type='substring')

    # Verify we have one more change
    assert len(stanza2._changes) == existing_change_count + 1

    # Now add to collection
    collection += stanza2

    # Verify addition logging preserved existing changes
    assert len(stanza2._changes) == existing_change_count + 2

    # Verify the last change is the addition
    last_change = stanza2._changes[-1]
    assert last_change.change_type == "addition"


@patch('builtins.print')
def test_batch_operation_logging(mock_print, collection):
    """Test logging behaviour in batch operations"""
    # Create multiple new stanzas
    new_stanzas = []
    for i in range(3):
        stanza = ConfigStanza(
            prefix=("ltm", "node"),
            name=f"192.168.1.{i + 20}",
            config_lines=[f"address 192.168.1.{i + 20}"]
        )
        new_stanzas.append(stanza)

    # Clear changes
    for stanza in new_stanzas:
        stanza._changes.clear()

    # Add all stanzas in batch
    collection += new_stanzas

    # Verify each stanza was logged
    for stanza in new_stanzas:
        assert len(stanza._changes) == 1
        change = stanza._changes[0]
        assert change.change_type == "addition"
        assert change.new_content == "Added to StanzaCollection"


@pytest.mark.parametrize("operation_type", [
    "iadd_single",
    "iadd_multiple",
    "add_operator",
    "collection_to_collection"
])
@patch('builtins.print')
def test_logging_operation_types(mock_print, collection, test_stanzas, operation_type):
    """Parameterised test for different addition operation types"""
    _, stanza2, stanza3 = test_stanzas

    # Clear existing changes
    stanza2._changes.clear()
    stanza3._changes.clear()

    if operation_type == "iadd_single":
        collection += stanza2
        assert len(stanza2._changes) == 1

    elif operation_type == "iadd_multiple":
        collection += [stanza2, stanza3]
        assert len(stanza2._changes) == 1
        assert len(stanza3._changes) == 1

    elif operation_type == "add_operator":
        new_collection = collection + stanza2
        assert len(stanza2._changes) == 1
        assert new_collection is not collection

    elif operation_type == "collection_to_collection":
        collection2 = StanzaCollection([stanza2, stanza3])
        collection += collection2
        assert len(stanza2._changes) == 1
        assert len(stanza3._changes) == 1


def test_change_id_uniqueness(test_stanzas):
    """Test that auto-generated change IDs are unique"""
    _, stanza2, _ = test_stanzas

    # Clear changes
    stanza2._changes.clear()

    # Add multiple times to generate multiple change IDs
    change_ids = set()
    for i in range(5):
        stanza2.log_addition(f"collection_{i}")
        change_ids.add(stanza2._changes[-1].change_id)

    # Verify all change IDs are unique
    assert len(change_ids) == 5


def test_logging_with_custom_collection_name(test_stanzas):
    """Test logging with custom collection names"""
    _, stanza2, _ = test_stanzas

    # Clear changes
    stanza2._changes.clear()

    # Test different collection names
    collection_names = ["my_custom_collection", "prod_config", "backup_set_1"]

    for name in collection_names:
        stanza2.log_addition(name)

    # Verify each addition was logged with correct collection name
    assert len(stanza2._changes) == 3
    for i, name in enumerate(collection_names):
        change = stanza2._changes[i]
        assert change.new_content == f"Added to {name}"