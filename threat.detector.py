# AI-Driven Threat Detection System
# Author: Poonam Uttam Manna
# Description: Basic log monitoring and 
# anomaly detection for SOC automation

import pandas as pd
import numphy as np
from datetime import datetime

# Sample security log data
def generate_sample_logs():
    logs = {
        'timestamp': [datetime.now()],
        'ip_address': ['192.168.1.1'],
        'event_type': ['login_attempt'],
        'status': ['failed'],
        'attempts': [5]
    }
    return pd.DataFrame(logs)

# Basic threat detection function
def detect_threats(logs):
    threats = []
    for index, row in logs.iterrows():
        # Flag if more than 3 failed attempts
        if row['attempts'] > 3:
            threats.append({
                'ip': row['ip_address'],
                'threat': 'Brute Force Attempt',
                'severity': 'HIGH',
                'time': row['timestamp']
            })
    return threats

# Main function
def main():
    print("=== AI-Driven Threat Detection ===")
    print("Scanning security logs...")
    
    logs = generate_sample_logs()
    threats = detect_threats(logs)
    
    if threats:
        print(f"\n {len(threats)} threat(s) detected!")
        for threat in threats:
            print(f"IP: {threat['ip']}")
            print(f"Threat: {threat['threat']}")
            print(f"Severity: {threat['severity']}")
    else:
        print("✅ No threats detected")

if __name__ == "__main__":
    main()
