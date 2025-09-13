import pytest
from unittest.mock import Mock, patch
from f5_config_parser.stanza import ConfigStanza
from f5_config_parser.monitored_list import MonitoredList
from f5_config_parser.change_record import ChangeRecord


class TestConfigStanzaPropertySetter:

    def test_initial_assignment_no_logging(self):
        """Test that initial config_lines assignment during __init__ doesn't create change records"""
        initial_lines = ["    destination 10.1.1.1:80", "    pool /Common/web_pool"]

        stanza = ConfigStanza(
            prefix=("ltm", "virtual"),
            name="/Common/test_vs",
            config_lines=initial_lines
        )

        # Should have no changes logged during initial assignment
        assert len(stanza._changes) == 0

        # Should be a MonitoredList
        assert isinstance(stanza.config_lines, MonitoredList)
        assert list(stanza.config_lines) == initial_lines

    def test_subsequent_assignment_creates_change_record(self):
        """Test that subsequent assignments to config_lines create change records"""
        initial_lines = ["    destination 10.1.1.1:80", "    pool /Common/web_pool"]
        new_lines = ["    destination 10.1.1.2:80", "    pool /Common/new_pool"]

        stanza = ConfigStanza(
            prefix=("ltm", "virtual"),
            name="/Common/test_vs",
            config_lines=initial_lines
        )

        # Verify no changes initially
        assert len(stanza._changes) == 0

        # Replace config lines
        stanza.config_lines = new_lines

        # Should have one change record
        assert len(stanza._changes) == 1

        change = stanza._changes[0]
        assert change.change_type == "total_replacement"
        assert change.source_operation == "config_lines_assignment"
        assert change.line_index == -1
        assert change.old_content == initial_lines
        assert change.new_content == new_lines

    def test_multiple_reassignments_create_multiple_records(self):
        """Test that multiple reassignments create separate change records"""
        initial_lines = ["    destination 10.1.1.1:80"]
        second_lines = ["    destination 10.1.1.2:80"]
        third_lines = ["    destination 10.1.1.3:80", "    pool /Common/pool"]

        stanza = ConfigStanza(
            prefix=("ltm", "virtual"),
            name="/Common/test_vs",
            config_lines=initial_lines
        )

        # First reassignment
        stanza.config_lines = second_lines
        assert len(stanza._changes) == 1
        assert stanza._changes[0].old_content == initial_lines
        assert stanza._changes[0].new_content == second_lines

        # Second reassignment
        stanza.config_lines = third_lines
        assert len(stanza._changes) == 2
        assert stanza._changes[1].old_content == second_lines
        assert stanza._changes[1].new_content == third_lines

    def test_cache_invalidation_called_on_reassignment(self):
        """Test that _invalidate_cache is called when config_lines is reassigned"""
        initial_lines = ["    destination 10.1.1.1:80"]
        new_lines = ["    destination 10.1.1.2:80"]

        stanza = ConfigStanza(
            prefix=("ltm", "virtual"),
            name="/Common/test_vs",
            config_lines=initial_lines
        )

        # Mock the _invalidate_cache method
        with patch.object(stanza, '_invalidate_cache') as mock_invalidate:
            stanza.config_lines = new_lines

            # Should have been called once during reassignment
            mock_invalidate.assert_called_once()

    def test_cache_invalidation_not_called_on_initial_assignment(self):
        """Test that _invalidate_cache is NOT called during initial assignment"""
        initial_lines = ["    destination 10.1.1.1:80"]

        with patch('f5_config_parser.stanza.ConfigStanza._invalidate_cache') as mock_invalidate:
            stanza = ConfigStanza(
                prefix=("ltm", "virtual"),
                name="/Common/test_vs",
                config_lines=initial_lines
            )

            # Should not have been called during initialisation
            mock_invalidate.assert_not_called()

    def test_monitored_list_callback_properly_set(self):
        """Test that the MonitoredList gets the correct invalidate callback"""
        initial_lines = ["    destination 10.1.1.1:80"]

        stanza = ConfigStanza(
            prefix=("ltm", "virtual"),
            name="/Common/test_vs",
            config_lines=initial_lines
        )

        # Get the callback from the MonitoredList
        stored_callback = stanza.config_lines.invalidate_callback
        original_method = stanza._invalidate_cache

        # The method objects themselves may be different (different IDs)
        assert stored_callback == original_method

        # But they should be bound to the same instance and function
        assert stored_callback.__self__ is original_method.__self__
        assert stored_callback.__func__ is original_method.__func__

        # Verify the callback is callable and not None
        assert callable(stored_callback)
        assert stored_callback is not None

        # Test that calling the stored callback actually works by checking side effects
        # First, set up some cached data
        _ = stanza.parsed_config  # This will populate the cache
        assert stanza._parsed_config is not None

        # Call the stored callback
        stored_callback()

        # Verify cache was cleared
        assert stanza._parsed_config is None
        assert stanza._dependencies is None

    def test_reassignment_creates_new_monitored_list_instance(self):
        """Test that reassignment creates a completely new MonitoredList instance"""
        initial_lines = ["    destination 10.1.1.1:80"]
        new_lines = ["    destination 10.1.1.2:80"]

        stanza = ConfigStanza(
            prefix=("ltm", "virtual"),
            name="/Common/test_vs",
            config_lines=initial_lines
        )

        original_list_id = id(stanza.config_lines)

        # Reassign
        stanza.config_lines = new_lines

        # Should be a different object
        assert id(stanza.config_lines) != original_list_id
        assert isinstance(stanza.config_lines, MonitoredList)
        assert list(stanza.config_lines) == new_lines

    def test_empty_list_reassignment(self):
        """Test reassignment with empty list"""
        initial_lines = ["    destination 10.1.1.1:80", "    pool /Common/web_pool"]

        stanza = ConfigStanza(
            prefix=("ltm", "virtual"),
            name="/Common/test_vs",
            config_lines=initial_lines
        )

        # Reassign to empty list
        stanza.config_lines = []

        assert len(stanza._changes) == 1
        change = stanza._changes[0]
        assert change.old_content == initial_lines
        assert change.new_content == []
        assert list(stanza.config_lines) == []

    def test_update_config_lines_method_uses_setter(self):
        """Test that update_config_lines method properly uses the setter"""
        initial_lines = ["    destination 10.1.1.1:80"]
        new_lines = ["    destination 10.1.1.2:80", "    pool /Common/pool"]

        stanza = ConfigStanza(
            prefix=("ltm", "virtual"),
            name="/Common/test_vs",
            config_lines=initial_lines
        )

        # Use the update method
        stanza.config_lines = new_lines

        # Should have logged the change via the setter
        assert len(stanza._changes) == 1
        assert stanza._changes[0].change_type == "total_replacement"
        assert stanza._changes[0].source_operation == "config_lines_assignment"
        assert list(stanza.config_lines) == new_lines

    @patch('builtins.print')
    def test_print_output_on_reassignment(self, mock_print):
        """Test that reassignment prints the expected log message"""
        initial_lines = ["    destination 10.1.1.1:80"]
        new_lines = ["    destination 10.1.1.2:80", "    pool /Common/pool"]

        stanza = ConfigStanza(
            prefix=("ltm", "virtual"),
            name="/Common/test_vs",
            config_lines=initial_lines
        )

        stanza.config_lines = new_lines

        # Check that print was called with expected message
        mock_print.assert_called_once()
        call_args = mock_print.call_args[0][0]
        assert "config_lines_assignment" in call_args
        assert "replaced 1 lines with 2 lines" in call_args

    @patch('builtins.print')
    def test_no_print_output_on_initial_assignment(self, mock_print):
        """Test that initial assignment doesn't print anything"""
        initial_lines = ["    destination 10.1.1.1:80"]

        stanza = ConfigStanza(
            prefix=("ltm", "virtual"),
            name="/Common/test_vs",
            config_lines=initial_lines
        )

        # Should not have printed anything during initialisation
        mock_print.assert_not_called()