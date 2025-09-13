from f5_config_parser.change_record import ChangeRecord
from datetime import datetime
from typing import Optional, List, Callable
import uuid


class MonitoredList(list):
    def __init__(self, *args, change_log: Optional[List] = None, invalidate_callback: Optional[Callable] = None,
                 **kwargs):
        super().__init__(*args, **kwargs)
        if change_log is None:
            raise ValueError("A change log list must be provided.")
        self.change_log = change_log
        self.invalidate_callback = invalidate_callback

    def _log_change(self, **kwargs):
        ctx = getattr(self, '_current_operation_context', {})
        record_data = {**ctx, **kwargs}

        change_record = ChangeRecord(
            change_id=record_data.get("change_id", str(uuid.uuid4())[:8]),
            timestamp=datetime.now(),
            line_index=record_data.get("line_index", -1),
            old_content=record_data.get("old_content", "N/A"),
            new_content=record_data.get("new_content", "N/A"),
            search_pattern=record_data.get("search_pattern", "N/A"),
            replacement=record_data.get("replacement", "N/A"),
            match_found=record_data.get("match_found", "N/A"),
            change_type=record_data.get("change_type", "modification"),
            source_operation=record_data.get("source_operation", "direct_assignment")
        )
        self.change_log.append(change_record)
        print(f"Logged change: {change_record.source_operation} on line {change_record.line_index}")

        # Call the invalidation callback if provided
        if self.invalidate_callback:
            self.invalidate_callback()

    def __setitem__(self, index, value):
        old_value = self[index]
        self._log_change(
            line_index=index,
            old_content=old_value,
            new_content=value,
            change_type="modification"
        )
        super().__setitem__(index, value)

    def append(self, item):
        self._log_change(
            line_index=len(self),
            old_content="N/A",
            new_content=item,
            change_type="append",
            source_operation="append_method"
        )
        super().append(item)

    def pop(self, index=-1):
        if len(self) == 0:
            raise IndexError("pop from empty list")

        old_value = self[index]
        self._log_change(
            line_index=index if index >= 0 else len(self) + index,
            old_content=old_value,
            new_content="N/A",
            change_type="removal",
            source_operation="pop_method"
        )
        return super().pop(index)

    def extend(self, iterable):
        start_index = len(self)
        items = list(iterable)

        # Only log if there are items to extend
        if items:
            self._log_change(
                line_index=start_index,
                old_content="N/A",
                new_content=items,  # Log the entire list being added
                change_type="extend",
                source_operation="extend_method"
            )

        super().extend(items)

    def insert(self, index, item):
        self._log_change(
            line_index=index,
            old_content="N/A",
            new_content=item,
            change_type="insertion",
            source_operation="insert_method"
        )
        super().insert(index, item)

    def remove(self, value):
        try:
            index = self.index(value)
            self._log_change(
                line_index=index,
                old_content=value,
                new_content="N/A",
                change_type="removal",
                source_operation="remove_method"
            )
            super().remove(value)
        except ValueError:
            raise ValueError(f"{value} not in list")

    def __delitem__(self, index):
        if isinstance(index, slice):
            # Handle slice deletion
            indices = range(*index.indices(len(self)))
            if indices:
                deleted_items = [self[i] for i in indices]
                self._log_change(
                    line_index=index.start or 0,
                    old_content=deleted_items,
                    new_content="N/A",
                    change_type="slice_deletion",
                    source_operation="del_slice"
                )
        else:
            # Handle single item deletion
            old_value = self[index]
            self._log_change(
                line_index=index,
                old_content=old_value,
                new_content="N/A",
                change_type="removal",
                source_operation="del_item"
            )

        super().__delitem__(index)

    def with_context(self, **kwargs):
        class ContextManager:
            def __init__(self, monitored_list, new_context):
                self.monitored_list = monitored_list
                self.new_context = new_context
                self.previous_context = None

            def __enter__(self):
                # Save the previous context if it exists
                self.previous_context = getattr(self.monitored_list, '_current_operation_context', None)
                # Set the new context
                self.monitored_list._current_operation_context = self.new_context

            def __exit__(self, exc_type, exc_val, exc_tb):
                # Restore the previous context or remove if none existed
                if self.previous_context is not None:
                    self.monitored_list._current_operation_context = self.previous_context
                else:
                    if hasattr(self.monitored_list, '_current_operation_context'):
                        del self.monitored_list._current_operation_context

        return ContextManager(self, kwargs)