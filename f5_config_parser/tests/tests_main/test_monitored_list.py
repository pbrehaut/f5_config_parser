import pytest
from unittest.mock import Mock, patch
from datetime import datetime

from f5_config_parser.monitored_list import MonitoredList


class TestMonitoredList:

    def test_init_requires_change_log(self):
        """Test that MonitoredList requires a change_log parameter."""
        with pytest.raises(ValueError, match="A change log list must be provided"):
            MonitoredList()

    def test_init_with_change_log(self):
        """Test successful initialisation with change_log."""
        change_log = []
        monitored_list = MonitoredList(change_log=change_log)
        assert monitored_list.change_log is change_log
        assert len(monitored_list) == 0

    def test_init_with_initial_data(self):
        """Test initialisation with initial data."""
        change_log = []
        initial_data = [1, 2, 3]
        monitored_list = MonitoredList(initial_data, change_log=change_log)
        assert list(monitored_list) == initial_data
        assert monitored_list.change_log is change_log

    def test_init_with_invalidate_callback(self):
        """Test initialisation with invalidate callback."""
        change_log = []
        callback = Mock()
        monitored_list = MonitoredList(change_log=change_log, invalidate_callback=callback)
        assert monitored_list.invalidate_callback is callback


class TestChangeLogging:

    def test_setitem_logs_change(self):
        """Test that setting an item logs a change."""
        change_log = []
        monitored_list = MonitoredList([1, 2, 3], change_log=change_log)

        monitored_list[1] = 99

        assert len(change_log) == 1
        record = change_log[0]
        assert record.line_index == 1
        assert record.old_content == 2
        assert record.new_content == 99
        assert record.change_type == "modification"

    def test_append_logs_change(self):
        """Test that append logs a change."""
        change_log = []
        monitored_list = MonitoredList([1, 2], change_log=change_log)

        monitored_list.append(3)

        assert len(change_log) == 1
        record = change_log[0]
        assert record.line_index == 2
        assert record.old_content == "N/A"
        assert record.new_content == 3
        assert record.change_type == "append"
        assert record.source_operation == "append_method"

    def test_pop_logs_change(self):
        """Test that pop logs a change."""
        change_log = []
        monitored_list = MonitoredList([1, 2, 3], change_log=change_log)

        result = monitored_list.pop()

        assert result == 3
        assert len(change_log) == 1
        record = change_log[0]
        assert record.line_index == 2
        assert record.old_content == 3
        assert record.new_content == "N/A"
        assert record.change_type == "removal"
        assert record.source_operation == "pop_method"

    def test_pop_with_index(self):
        """Test pop with specific index."""
        change_log = []
        monitored_list = MonitoredList([1, 2, 3], change_log=change_log)

        result = monitored_list.pop(0)

        assert result == 1
        assert len(change_log) == 1
        record = change_log[0]
        assert record.line_index == 0
        assert record.old_content == 1

    def test_pop_negative_index(self):
        """Test pop with negative index."""
        change_log = []
        monitored_list = MonitoredList([1, 2, 3], change_log=change_log)

        result = monitored_list.pop(-2)

        assert result == 2
        assert len(change_log) == 1
        record = change_log[0]
        assert record.line_index == 1  # -2 converted to positive index

    def test_pop_empty_list_raises_error(self):
        """Test that popping from empty list raises IndexError."""
        change_log = []
        monitored_list = MonitoredList(change_log=change_log)

        with pytest.raises(IndexError, match="pop from empty list"):
            monitored_list.pop()

    def test_extend_logs_changes(self):
        """Test that extend logs changes for each item."""
        change_log = []
        monitored_list = MonitoredList([1], change_log=change_log)

        monitored_list.extend([2, 3, 4])

        assert len(change_log) == 1
        for i, record in enumerate(change_log):
            assert record.line_index == i + 1
            assert record.old_content == "N/A"
            assert record.new_content == [2, 3, 4]
            assert record.change_type == "extend"
            assert record.source_operation == "extend_method"

    def test_insert_logs_change(self):
        """Test that insert logs a change."""
        change_log = []
        monitored_list = MonitoredList([1, 3], change_log=change_log)

        monitored_list.insert(1, 2)

        assert len(change_log) == 1
        record = change_log[0]
        assert record.line_index == 1
        assert record.old_content == "N/A"
        assert record.new_content == 2
        assert record.change_type == "insertion"
        assert record.source_operation == "insert_method"

    def test_remove_logs_change(self):
        """Test that remove logs a change."""
        change_log = []
        monitored_list = MonitoredList([1, 2, 3], change_log=change_log)

        monitored_list.remove(2)

        assert len(change_log) == 1
        record = change_log[0]
        assert record.line_index == 1
        assert record.old_content == 2
        assert record.new_content == "N/A"
        assert record.change_type == "removal"
        assert record.source_operation == "remove_method"

    def test_remove_nonexistent_raises_error(self):
        """Test that removing non-existent item raises ValueError."""
        change_log = []
        monitored_list = MonitoredList([1, 2, 3], change_log=change_log)

        with pytest.raises(ValueError, match="99 not in list"):
            monitored_list.remove(99)

    def test_del_item_logs_change(self):
        """Test that deleting an item logs a change."""
        change_log = []
        monitored_list = MonitoredList([1, 2, 3], change_log=change_log)

        del monitored_list[1]

        assert len(change_log) == 1
        record = change_log[0]
        assert record.line_index == 1
        assert record.old_content == 2
        assert record.new_content == "N/A"
        assert record.change_type == "removal"
        assert record.source_operation == "del_item"

    def test_del_slice_logs_change(self):
        """Test that deleting a slice logs a change."""
        change_log = []
        monitored_list = MonitoredList([1, 2, 3, 4, 5], change_log=change_log)

        del monitored_list[1:3]

        assert len(change_log) == 1
        record = change_log[0]
        assert record.line_index == 1
        assert record.old_content == [2, 3]
        assert record.new_content == "N/A"
        assert record.change_type == "slice_deletion"
        assert record.source_operation == "del_slice"

    def test_del_empty_slice(self):
        """Test deleting an empty slice."""
        change_log = []
        monitored_list = MonitoredList([1, 2, 3], change_log=change_log)

        del monitored_list[1:1]  # Empty slice

        # Should NOT log anything since no actual change occurred
        assert len(change_log) == 0
        assert list(monitored_list) == [1, 2, 3]  # List unchanged


class TestInvalidateCallback:

    def test_callback_called_on_setitem(self):
        """Test that invalidate callback is called on setitem."""
        change_log = []
        callback = Mock()
        monitored_list = MonitoredList([1, 2], change_log=change_log, invalidate_callback=callback)

        monitored_list[0] = 99

        callback.assert_called_once()

    def test_callback_called_on_append(self):
        """Test that invalidate callback is called on append."""
        change_log = []
        callback = Mock()
        monitored_list = MonitoredList(change_log=change_log, invalidate_callback=callback)

        monitored_list.append(1)

        callback.assert_called_once()

    def test_callback_called_on_all_operations(self):
        """Test that callback is called on all modifying operations."""
        change_log = []
        callback = Mock()
        monitored_list = MonitoredList([1, 2, 3], change_log=change_log, invalidate_callback=callback)

        monitored_list.append(4)
        monitored_list.pop()
        monitored_list.extend([5, 6])
        monitored_list.insert(0, 0)
        monitored_list.remove(1)
        del monitored_list[0]

        assert callback.call_count == 6


class TestContextManager:

    def test_with_context_sets_operation_context(self):
        """Test that with_context sets operation context for logging."""
        change_log = []
        monitored_list = MonitoredList([1], change_log=change_log)

        with monitored_list.with_context(change_id="test123", search_pattern="test"):
            monitored_list[0] = 99

        assert len(change_log) == 1
        record = change_log[0]
        assert record.change_id == "test123"
        assert record.search_pattern == "test"

    def test_context_cleared_after_with_block(self):
        """Test that context is cleared after with block."""
        change_log = []
        monitored_list = MonitoredList([1], change_log=change_log)

        with monitored_list.with_context(change_id="test123"):
            pass

        # Context should be cleared
        assert not hasattr(monitored_list, '_current_operation_context')

    def test_multiple_operations_in_context(self):
        """Test multiple operations within same context."""
        change_log = []
        monitored_list = MonitoredList([1, 2], change_log=change_log)

        with monitored_list.with_context(change_id="batch_op"):
            monitored_list.append(3)
            monitored_list[0] = 99

        assert len(change_log) == 2
        assert all(record.change_id == "batch_op" for record in change_log)


class TestChangeRecordContent:

    @patch('uuid.uuid4')
    def test_change_record_uuid_generation(self, mock_uuid):
        """Test that change records generate UUIDs when no change_id provided."""
        # Mock the string representation of uuid4(), not the hex attribute
        mock_uuid.return_value.__str__ = Mock(return_value="abcdef12-3456-7890-abcd-ef1234567890")
        change_log = []
        monitored_list = MonitoredList([1], change_log=change_log)

        monitored_list[0] = 2

        record = change_log[0]
        assert record.change_id == "abcdef12"

    def test_change_record_timestamp(self):
        """Test that change records have timestamps."""
        change_log = []
        monitored_list = MonitoredList([1], change_log=change_log)

        before = datetime.now()
        monitored_list[0] = 2
        after = datetime.now()

        record = change_log[0]
        assert before <= record.timestamp <= after

    def test_change_record_defaults(self):
        """Test change record default values."""
        change_log = []
        monitored_list = MonitoredList([1], change_log=change_log)

        monitored_list.append(2)

        record = change_log[0]
        assert record.match_found == "N/A"
        assert record.replacement == "N/A"
        assert record.search_pattern == "N/A"


class TestListBehaviour:

    def test_behaves_like_normal_list(self):
        """Test that MonitoredList behaves like a normal list for basic operations."""
        change_log = []
        monitored_list = MonitoredList([1, 2, 3], change_log=change_log)

        # Test indexing
        assert monitored_list[0] == 1
        assert monitored_list[-1] == 3

        # Test length
        assert len(monitored_list) == 3

        # Test iteration
        assert list(monitored_list) == [1, 2, 3]

        # Test membership
        assert 2 in monitored_list
        assert 4 not in monitored_list

    def test_slicing_works(self):
        """Test that slicing works normally."""
        change_log = []
        monitored_list = MonitoredList([1, 2, 3, 4, 5], change_log=change_log)

        assert monitored_list[1:4] == [2, 3, 4]
        assert monitored_list[:2] == [1, 2]
        assert monitored_list[2:] == [3, 4, 5]


class TestEdgeCases:

    def test_extend_with_empty_iterable(self):
        """Test extending with empty iterable."""
        change_log = []
        monitored_list = MonitoredList([1], change_log=change_log)

        monitored_list.extend([])

        assert len(monitored_list) == 1
        assert len(change_log) == 0  # No changes logged for empty extend

    def test_insert_at_end(self):
        """Test inserting at the end of the list."""
        change_log = []
        monitored_list = MonitoredList([1, 2], change_log=change_log)

        monitored_list.insert(2, 3)

        assert list(monitored_list) == [1, 2, 3]
        assert change_log[0].line_index == 2

    def test_insert_at_beginning(self):
        """Test inserting at the beginning of the list."""
        change_log = []
        monitored_list = MonitoredList([2, 3], change_log=change_log)

        monitored_list.insert(0, 1)

        assert list(monitored_list) == [1, 2, 3]
        assert change_log[0].line_index == 0

    def test_remove_first_occurrence(self):
        """Test that remove only removes first occurrence."""
        change_log = []
        monitored_list = MonitoredList([1, 2, 2, 3], change_log=change_log)

        monitored_list.remove(2)

        assert list(monitored_list) == [1, 2, 3]
        assert change_log[0].line_index == 1  # First occurrence at index 1


class TestPrintOutput:

    def test_log_change_prints_message(self, capsys):
        """Test that _log_change prints a message."""
        change_log = []
        monitored_list = MonitoredList([1], change_log=change_log)

        monitored_list[0] = 2

        captured = capsys.readouterr()
        assert "Logged change: direct_assignment on line 0" in captured.out


class TestComplexScenarios:

    def test_multiple_operations_sequence(self):
        """Test a sequence of multiple operations."""
        change_log = []
        callback = Mock()
        monitored_list = MonitoredList(change_log=change_log, invalidate_callback=callback)

        # Perform sequence of operations
        monitored_list.append(1)
        monitored_list.append(2)
        monitored_list.insert(1, 1.5)
        monitored_list[2] = 2.5
        monitored_list.remove(1.5)
        monitored_list.pop()

        # Verify final state
        assert list(monitored_list) == [1]

        # Verify all changes logged
        assert len(change_log) == 6

        # Verify callback called for each operation
        assert callback.call_count == 6

    def test_context_with_complex_operations(self):
        """Test context manager with complex operations."""
        change_log = []
        monitored_list = MonitoredList([1, 2, 3], change_log=change_log)

        with monitored_list.with_context(
                change_id="bulk_update",
                search_pattern="pattern123",
                replacement="replacement456"
        ):
            monitored_list.extend([4, 5])
            monitored_list[0] = 99
            del monitored_list[1:3]

        assert len(change_log) == 3  # extend adds 1, setitem adds 1, del adds 1

        # All should have the context
        for record in change_log:
            assert record.change_id == "bulk_update"
            assert record.search_pattern == "pattern123"
            assert record.replacement == "replacement456"

    def test_nested_context_managers(self):
        """Test that context managers can be nested."""
        change_log = []
        monitored_list = MonitoredList([1], change_log=change_log)

        with monitored_list.with_context(change_id="outer"):
            monitored_list.append(2)

            with monitored_list.with_context(change_id="inner"):
                monitored_list.append(3)

            monitored_list.append(4)

        assert len(change_log) == 3
        assert change_log[0].change_id == "outer"
        assert change_log[1].change_id == "inner"
        assert change_log[2].change_id == "outer"


@pytest.fixture
def sample_monitored_list():
    """Fixture providing a sample MonitoredList for tests."""
    change_log = []
    return MonitoredList([1, 2, 3], change_log=change_log), change_log


class TestFixtureUsage:

    def test_with_fixture(self, sample_monitored_list):
        """Test using the fixture."""
        monitored_list, change_log = sample_monitored_list

        monitored_list.append(4)

        assert len(monitored_list) == 4
        assert len(change_log) == 1