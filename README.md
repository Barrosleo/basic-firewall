# Basic Firewall

This tool is a simple firewall that can block or allow traffic based on predefined rules.

## How to Use

1. Clone the repository.
2. Run the `firewall.py` script with administrative privileges.
3. The script will capture and filter packets based on the defined rules.

## Example

```python
rules = [
    {"action": "allow", "protocol": "tcp", "port": 80},
    {"action": "allow", "protocol": "tcp", "port": 443},
    {"action": "block", "protocol": "tcp", "port": 22},
]
