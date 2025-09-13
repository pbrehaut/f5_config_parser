from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Union
import re


@dataclass
class ChangeRecord:
    """Records a stanza change or replacement operation"""
    change_id: str
    timestamp: datetime
    line_index: int
    old_content: str
    new_content: str
    search_pattern: Union[str, re.Pattern]
    replacement: str
    match_found: str
    change_type: str
    source_operation: Optional[str] = None  # Default for backward compatibility
