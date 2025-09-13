import re


def extract_fields(input_string, required_fields=None):
    """
    Extract various fields from input strings using separate regex patterns.

    Args:
        input_string (str): The input string to parse
        required_fields (list): List of field names that must be present.
                               If None, defaults to ['ip_address']

    Returns:
        dict: Dictionary containing extracted fields
    """
    if required_fields is None:
        required_fields = ['ip_address']

    # Initialize result dictionary
    result = {}

    # Define regex patterns for each field type
    patterns = {
        'partition': r'/([^/]+)/',  # Partition between forward slashes
        'ip_address': r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',  # IPv4 address
        'route_domain': r'%(\d+)',  # Route domain after % symbol
        'port': r':(\d+)$',  # Port number at end after colon
        'service': r':([a-zA-Z][a-zA-Z0-9]*?)(?:%|$)',  # Service name after colon
    }

    # Extract each field type
    for field_name, pattern in patterns.items():
        match = re.search(pattern, input_string)
        if match:
            result[field_name] = match.group(1)

    # Special handling for port vs service disambiguation
    # If we found both, we need to determine which colon-prefixed value is which
    colon_matches = re.findall(r':(\w+)', input_string)
    if colon_matches:
        for match in colon_matches:
            if match.isdigit():
                result['port'] = match
            else:
                result['service'] = match

    # Validation - raise exceptions for missing required fields
    for field in required_fields:
        if field not in result:
            raise ValueError(f"Required field '{field}' not found in input string: '{input_string}'")

    return result