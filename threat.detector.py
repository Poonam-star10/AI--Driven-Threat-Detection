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
        print("No threats detected")

if __name__ == "__main__":
    main()
# Vulnerability Scanner Function
def scan_vulnerabilities(logs):
    vulnerabilities = []
    for index, row in logs.iterrows():
        # SQL Injection attempt
        if 'sql' in str(row['event_type']).lower():
            vulnerabilities.append({
                'ip': row['ip_address'],
                'type': 'SQL Injection Attempt',
                'severity': 'CRITICAL',
                'cvss_score': 9.8
            })
        # Check for port scanning
        if row['attempts'] > 10:
            vulnerabilities.append({
                'ip': row['ip_address'],
                'type': 'Port Scan Detected',
                'severity': 'HIGH',
                'cvss_score': 7.5
            })
    return vulnerabilities
# Machine Learning Anomaly Detection
from sklearn.ensemble import IsolationForest
import numpy as np

def ml_anomaly_detection(attempts_data):
    """
    Uses AI to detect unusual behaviour
    in security logs automatically
    """
    # Create AI model
    model = IsolationForest(
        contamination=0.1,
        random_state=42
    )
    
    # Prepare data for AI model
    data = np.array(attempts_data).reshape(-1, 1)
    
    # Train the AI model
    model.fit(data)
    
    # AI predicts anomalies
    # -1 means anomaly, 1 means normal
    predictions = model.predict(data)
    
    anomalies = []
    for i, pred in enumerate(predictions):
        if pred == -1:
            anomalies.append({
                'index': i,
                'attempts': attempts_data[i],
                'status': 'ANOMALY DETECTED',
                'severity': 'HIGH',
                'action': 'INVESTIGATE IMMEDIATELY'
            })
    return anomalies

# Automated Security Report Generator
def generate_security_report(
    threats, vulnerabilities, anomalies):
    """
    Generates automated security report
    This is the core SOC automation feature
    """
    print("\n" + "="*45)
    print("  AI-DRIVEN SOC SECURITY REPORT")
    print("="*45)
    print(f"Total Threats:         {len(threats)}")
    print(f"Total Vulnerabilities: {len(vulnerabilities)}")
    print(f"AI Anomalies:          {len(anomalies)}")
    print("="*45)
    
    # Print threats
    if threats:
        print("\n ACTIVE THREATS:")
        for t in threats:
            print(f"  IP: {t['ip']}")
            print(f"  Type: {t['threat']}")
            print(f"  Severity: {t['severity']}")
            print("  ---")
    
    # Print vulnerabilities        
    if vulnerabilities:
        print("\n VULNERABILITIES FOUND:")
        for v in vulnerabilities:
            print(f"  IP: {v['ip']}")
            print(f"  Type: {v['type']}")
            print(f"  CVSS Score: {v['cvss_score']}")
            print("  ---")
    
    # Print AI anomalies
    if anomalies:
        print("\n AI DETECTED ANOMALIES:")
        for a in anomalies:
            print(f"  Attempts: {a['attempts']}")
            print(f"  Status: {a['status']}")
            print(f"  Action: {a['action']}")
            print("  ---")
    
    print("\n Automated report complete!")
    print("="*45)

