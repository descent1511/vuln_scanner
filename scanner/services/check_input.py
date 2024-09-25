import re  # Import the regular expression module

# Define a function to validate the input data against various patterns
def validate_input(input_data):
    # Define regex patterns for different data types
    patterns = {
        'domain_name': r'^[a-zA-Z0-9-]{1,63}\.[a-zA-Z]{2,}$',  # Matches domain names like 'example.com'
        'ip_address': r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',  # Matches IPv4 addresses like '192.168.1.1'
        'hostname': r'^[a-zA-Z0-9-]{1,63}\.[a-zA-Z0-9-]{1,63}\.[a-zA-Z]{2,}$',  # Matches hostnames like 'host.example.com'
        'subdomain': r'^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$',  # Matches subdomains like 'sub.example.com'
        'subnet': r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.0\/\d{1,2}$',  # Matches subnet formats like '192.168.1.0/24'
        'bitcoin_address': r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$',  # Matches Bitcoin addresses
        'email': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$',  # Matches email addresses
        'phone_number': r'^\+?[1-9]\d{1,14}$',  # Matches international phone numbers in E.164 format
        'human_name': r'^[A-Za-z ]+$',  # Matches names containing alphabetic characters and spaces
        'username': r'^[a-zA-Z0-9_.-]+$',  # Matches usernames containing letters, numbers, underscores, dots, or hyphens
        'asn': r'^\d+$'  # Matches autonomous system numbers (ASN) which are numeric
    }

    # Iterate over each pattern to check if the input matches any of them
    for data_type, pattern in patterns.items():
        if re.match(pattern, input_data):  # Check if input matches the current pattern
            return data_type  # Return the type of input data if a match is found
    
    return "Invalid input"  # Return 'Invalid input' if no patterns match
