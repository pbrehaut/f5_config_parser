def is_conditional_line(line):
    """
    Check if a line contains a conditional statement, including those starting with }
    """
    conditional_keywords = ['if', 'when', 'else', 'elsif']
    line = line.strip()
    # Check for lines starting with conditional keywords
    if any(line.startswith(keyword) for keyword in conditional_keywords):
        return True
    # Check for lines starting with } followed by conditional keywords
    if line.startswith('}'):
        remaining_text = line[1:].strip()
        if any(remaining_text.startswith(keyword) for keyword in conditional_keywords):
            return True
    return False


def extract_unique_words(irule_lines):
    """
    Extracts unique words from F5 iRule contents, filtering out common keywords and syntax.

    Args:
       irule_lines (list): List of strings where each string is a line from the iRule

    Returns:
       set: Set of all unique words found in the iRule code
    """

    # Common TCL/iRule keywords and syntax elements to exclude
    EXCLUDE_WORDS = {
        '{', '}', '(', ')', '[', ']', '<', '>',
        'if', 'else', 'elseif', 'when', 'switch', 'foreach', 'while', 'for',
        'CLIENT_ACCEPTED', 'HTTP_REQUEST', 'HTTP_RESPONSE', 'SERVER_CONNECTED',
        'set', 'string', 'regexp', 'regsub', 'split', 'join', 'lindex', 'llength',
        'HTTP::uri', 'HTTP::host', 'HTTP::method', 'HTTP::header', 'HTTP::payload',
        'TCP::client_port', 'IP::client_addr', 'SSL::cert', 'log', 'CLIENTSSL_HANDSHAKE',
    }

    unique_words = set()

    for line in irule_lines:
        # Skip empty lines and comments
        if not line.strip() or line.strip().startswith('#'):
            continue

        # Split and clean words in one step using list comprehension
        cleaned_words = [word.strip('"\'{}()[]<>') for word in line.split()]

        # Filter and add valid words
        for cleaned_word in cleaned_words:
            if (cleaned_word not in EXCLUDE_WORDS
                    and not cleaned_word.startswith('$')
                    and '::' not in cleaned_word
                    and cleaned_word):  # Make sure it's not empty after stripping
                unique_words.add(cleaned_word)

    return unique_words


def extract_irule_flow(irule_lines):
    """
    Extracts F5 iRule actions with their conditional context.

    Args:
        irule_lines (list): List of strings where each string is a line from the iRule

    Returns:
        list: List of strings containing the detected actions with their conditions
    """
    # Common F5 iRule actions to look for
    action_keywords = [
        'pool',
        'HTTP::respond',
        'HTTP::redirect',
        'persist',
        'log',
        'event',
        'table',
        'after',
        'virtual',
        'drop',
        'reject',
        'discard',
        'return',
        'snat',
        'SSL::enable',
        'SSL::disable',
    ]

    irule_flow = []
    condition_stack = []

    for line in irule_lines:
        # Remove leading/trailing whitespace and extra spaces
        line = ' '.join(line.strip().split())

        # Skip empty lines and comments
        if not line or line.startswith('#'):
            continue

        if is_conditional_line(line):
            # If it starts with a closing brace, remove the previous condition
            if line.strip().startswith('}'):
                if condition_stack:
                    condition_stack.pop()
                # Extract the actual conditional part after the }
                conditional_part = line.strip()[1:].strip()
                if conditional_part:  # Only add if there's content after the }
                    condition_stack.append(conditional_part)
            else:
                condition_stack.append(line)
        elif '}' in line:
            if condition_stack:
                condition_stack.pop()

        # Check for actions
        action_found = False

        # Check if line starts with any of the action keywords
        for keyword in action_keywords:
            if line.startswith(keyword):
                action_found = True
                break

        if action_found:
            # Build the complete context string for irule_flow
            if condition_stack:
                context = " -> ".join(condition_stack)
                irule_flow.append(f"{context} -> {line}")
            else:
                irule_flow.append(line)

    return irule_flow


def extract_http_responses(irule_lines):
    """
    Extracts HTTP respond and redirect actions from F5 iRule contents.

    Args:
        irule_lines (list): List of strings where each string is a line from the iRule

    Returns:
        list: List of HTTP respond and redirect actions
    """
    http_responses = []

    for line in irule_lines:
        # Remove leading/trailing whitespace and extra spaces
        line = ' '.join(line.strip().split())

        # Skip empty lines and comments
        if not line or line.startswith('#'):
            continue

        # Track HTTP responses
        if line.startswith('HTTP::respond') or line.startswith('HTTP::redirect'):
            if line not in http_responses:
                http_responses.append(line)

    return http_responses


def parse_irule(irule_lines):
    """
    Analyzes F5 iRule contents and extracts actions with their conditional context.

    Args:
        irule_lines (list): List of strings where each string is a line from the iRule

    Returns:
        dict: Dictionary containing analysis results with the following keys:
            - irule_flow: List of strings containing the detected actions with their conditions
            - http_responses: List of HTTP respond and redirect actions
            - unique_words: Set of all unique words found in the iRule code
    """
    return {
        'irule_flow': extract_irule_flow(irule_lines),
        'http_responses': extract_http_responses(irule_lines),
        'unique_words': extract_unique_words(irule_lines)
    }
