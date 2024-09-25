import re

def validate_input(input_data):
    patterns = {
        'domain_name': r'^[a-zA-Z0-9-]{1,63}\.[a-zA-Z]{2,}$',
        'ip_address': r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
        'hostname': r'^[a-zA-Z0-9-]{1,63}\.[a-zA-Z0-9-]{1,63}\.[a-zA-Z]{2,}$',
        'subdomain': r'^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$',
        'subnet': r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.0\/\d{1,2}$',
        'bitcoin_address': r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$',
        'email': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$',
        'phone_number': r'^\+?[1-9]\d{1,14}$',
        'human_name': r'^[A-Za-z ]+$',
        'username': r'^[a-zA-Z0-9_.-]+$',
        'asn': r'^\d+$'
        # 'subdomain': r'^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$'  # Added subdomain pattern
    }

    for data_type, pattern in patterns.items():
        if re.match(pattern, input_data):
            return data_type
    
    return "Invalid input"

