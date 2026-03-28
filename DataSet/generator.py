import pandas as pd
import numpy as np
from faker import Faker
import random
from datetime import datetime, timedelta
import hashlib
import warnings
warnings.filterwarnings('ignore')

# Initialize Faker with supported locales
fake = Faker(['en_US', 'en_GB', 'en_IN'])
random.seed(42)
np.random.seed(42)

# Configuration
NUM_ROWS = 70000
START_DATE = datetime(2026, 3, 1, 0, 0, 0)

# Data Quality Configuration
NOISE_CONFIG = {
    'missing_rate': 0.12,
    'invalid_timestamp_rate': 0.02,
    'outlier_rate': 0.03,
    'duplicate_rate': 0.01,
    'corruption_rate': 0.005,
    'encoding_errors': 0.01,
}

# Log Sources
LOG_SOURCES = [
    'windows_security', 'sysmon', 'zeek', 'azure_ad', 'office365',
    'sharepoint', 'cloud_waf', 'github_actions', 'auditd', 'falco',
    'crowdstrike', 'sentinel_one', 'palo_alto', 'cisco_asa', 'aws_cloudtrail'
]

# Event mappings
EVENT_MAPPINGS = {
    'windows_security': ['4624', '4625', '4648', '4672', '4688', '4698', '4702'],
    'sysmon': ['1', '3', '7', '10', '11', '12', '13', '22'],
    'zeek': ['conn', 'http', 'ssl', 'dns', 'smb_files'],
    'azure_ad': ['SignIn', 'Audit', 'ApplicationManagement'],
    'office365': ['MailItemsAccessed', 'New-InboxRule', 'Send', 'FileDownloaded'],
    'sharepoint': ['FileDownloaded', 'FileUploaded', 'FileDeleted'],
    'cloud_waf': ['SQL_Injection', 'XSS', 'Path_Traversal'],
    'github_actions': ['workflow_run', 'job_execution', 'action_execution'],
    'auditd': ['SYSCALL', 'EXECVE', 'PATH', 'PROCTITLE'],
    'falco': ['shell_in_container', 'read_sensitive_file', 'write_binary_dir'],
    'crowdstrike': ['Detection', 'Prevention', 'Quarantine'],
    'sentinel_one': ['Threat', 'Suspicious', 'Blocked'],
    'palo_alto': ['TRAFFIC', 'THREAT', 'URL'],
    'cisco_asa': ['106001', '106023', '302015', '302016'],
    'aws_cloudtrail': ['ConsoleLogin', 'CreateUser', 'DeleteUser', 'CreateAccessKey']
}

def generate_hostname():
    """Generate realistic banking hostnames"""
    roles = ['WEB', 'APP', 'DB', 'WKS', 'DC', 'FS', 'GW', 'PROXY', 'MON', 'OPS', 
             'PAY', 'CORE', 'BRANCH', 'ATM', 'SWIFT', 'RISK', 'COMP', 'AUDIT']
    
    if random.random() < 0.3:
        roles = ['PAYMENT', 'CORE_BANK', 'TRADING', 'CRM', 'HR', 'FINANCE']
    
    role = random.choice(roles)
    num = random.randint(1, 99)
    environment = random.choice(['prod', 'uat', 'dev', 'dr', 'sandbox']) if random.random() < 0.4 else ''
    
    hostname = f"{role}-{num:02d}"
    if environment:
        hostname = f"{hostname}-{environment}"
    if random.random() < 0.5:
        domain = random.choice(['bank.internal', 'financial.local', 'core.banking', 'secure.bank'])
        hostname = f"{hostname}.{domain}"
    
    return hostname

def generate_username():
    """Generate realistic banking usernames"""
    patterns = []
    
    # Personal accounts
    first_names = [fake.first_name().lower() for _ in range(20)]
    last_names = [fake.last_name().lower() for _ in range(20)]
    
    for fn in first_names[:5]:
        for ln in last_names[:5]:
            patterns.append(f"{fn}.{ln}")
            patterns.append(f"{fn}_{ln}")
            patterns.append(f"{fn[0]}{ln}")
    
    # Service accounts
    service_roles = ['backup', 'monitor', 'deploy', 'scanner', 'audit', 'cicd', 
                     'replication', 'etl', 'reporting', 'archive', 'vault', 'secrets']
    
    for role in service_roles:
        patterns.append(f"svc_{role}")
        patterns.append(f"svc_{role}_prod")
    
    # Administrative accounts
    patterns.extend(['admin', 'root', 'sysadmin', 'domain_admin'])
    
    # Banking roles
    banking_roles = ['trading_user', 'settlement', 'compliance', 'fraud_analyst', 
                     'risk_manager', 'internal_audit', 'treasury']
    patterns.extend(banking_roles)
    
    selected = random.choice(patterns)
    
    if random.random() < 0.2:
        selected = f"{selected}{random.randint(1, 99)}"
    
    return selected

def generate_ip():
    """Generate realistic IP addresses"""
    if random.random() < 0.45:
        internal_types = [
            lambda: f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            lambda: f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            lambda: f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        ]
        return random.choice(internal_types)()
    else:
        return fake.ipv4()

def generate_command_line(process_name):
    """Generate realistic command lines"""
    base_commands = {
        'powershell': [
            "Get-Process | Where-Object {$_.CPU -gt 100}",
            "Get-Service | Where-Object {$_.Status -eq 'Running'}",
            f"Invoke-WebRequest -Uri https://{fake.domain_name()}/update.ps1 -OutFile C:\\Temp\\update.ps1",
            "Get-ADUser -Filter * -Properties LastLogon | Select-Object Name, LastLogon",
        ],
        'cmd': [
            "whoami /all",
            "ipconfig /all",
            "netstat -ano | findstr :445",
            f"ping {fake.domain_name()} -n 5",
            "systeminfo",
        ],
        'bash': [
            "ps aux | grep -v grep",
            "netstat -tulpn | grep LISTEN",
            f"curl -X GET https://{fake.domain_name()}/api/health",
            "cat /etc/passwd | grep -E '(/bin/bash|/bin/zsh)'",
        ],
        'sql': [
            "SELECT * FROM sys.dm_exec_requests WHERE status = 'running'",
            "xp_cmdshell 'whoami'",
            "BACKUP DATABASE FinanceDB TO DISK = 'Z:\\backups\\FinanceDB.bak'",
        ]
    }
    
    cmd_type = 'bash'
    if 'powershell' in process_name.lower():
        cmd_type = 'powershell'
    elif 'cmd' in process_name.lower():
        cmd_type = 'cmd'
    elif 'sql' in process_name.lower():
        cmd_type = 'sql'
    elif any(x in process_name.lower() for x in ['sh', 'bash', 'zsh']):
        cmd_type = 'bash'
    
    if cmd_type in base_commands and base_commands[cmd_type]:
        return random.choice(base_commands[cmd_type])
    
    return fake.sentence(nb_words=random.randint(3, 8))

def generate_file_path():
    """Generate realistic file paths"""
    path_types = [
        lambda: f"C:\\Windows\\System32\\{fake.file_name()}",
        lambda: f"C:\\Windows\\Temp\\{fake.file_name()}",
        lambda: f"C:\\Users\\{generate_username()}\\Documents\\{fake.file_name()}",
        lambda: f"Z:\\Finance\\{fake.date_this_year()}\\{fake.file_name()}",
        lambda: f"\\\\fileserver\\share\\{fake.word().capitalize()}\\{fake.file_name()}",
        lambda: f"/var/log/{fake.word()}/{fake.file_name()}.log",
        lambda: f"/etc/{fake.word()}/{fake.word()}.conf",
        lambda: f"/opt/banking/{fake.word()}/bin/{fake.file_name()}",
    ]
    
    return random.choice(path_types)()

def generate_process_name():
    """Generate realistic process names"""
    processes = [
        'powershell.exe', 'cmd.exe', 'explorer.exe', 'svchost.exe', 'lsass.exe',
        'sqlservr.exe', 'tomcat9.exe', 'nginx.exe', 'java.exe', 'python.exe',
        'WINWORD.EXE', 'EXCEL.EXE', 'OUTLOOK.EXE', 'chrome.exe',
        'sshd', 'systemd', 'kubelet', 'docker', 'prometheus',
    ]
    
    if random.random() < 0.3:
        version = f"v{random.randint(1, 10)}.{random.randint(0, 9)}"
        return f"{random.choice(processes)}_{version}"
    
    return random.choice(processes)

def generate_destination():
    """Generate realistic destinations with ports"""
    host = generate_hostname()
    ports = [22, 80, 443, 445, 3389, 1433, 3306, 5432, 8080, 8443, 9200, 27017]
    port = random.choice(ports)
    
    if random.random() < 0.2:
        banking_services = ['core-bank', 'payment-api', 'swift-gateway', 'crm', 'ledger']
        host = f"{random.choice(banking_services)}.{fake.domain_name()}"
    
    return f"{host}:{port}"

def generate_message(event, source, **kwargs):
    """Generate realistic log messages"""
    templates = {
        'windows_security': {
            '4624': f"An account was successfully logged on. Account: {kwargs.get('user', 'unknown')}, Source IP: {kwargs.get('ip', 'unknown')}",
            '4625': f"An account failed to log on. Account: {kwargs.get('user', 'unknown')}, Source IP: {kwargs.get('ip', 'unknown')}",
            '4688': f"A new process was created. Process: {kwargs.get('proc', 'unknown')}, Command line: {kwargs.get('cmd', '')}",
        },
        'sysmon': {
            '1': f"Process creation: {kwargs.get('proc', 'unknown')} with command line: {kwargs.get('cmd', '')}",
            '3': f"Network connection: {kwargs.get('proc', 'unknown')} connected to {kwargs.get('dest', 'unknown')}",
            '10': f"Process accessed: {kwargs.get('proc', '')} accessed {kwargs.get('target', '')}",
        },
        'azure_ad': {
            'SignIn': f"Sign-in activity for {kwargs.get('user', 'unknown')} from IP {kwargs.get('ip', 'unknown')}",
            'Audit': f"Audit log: {kwargs.get('action', 'unknown')} performed by {kwargs.get('user', 'unknown')}",
        }
    }
    
    if source in templates and event in templates[source]:
        return templates[source][event]
    
    banking_terms = ['transaction', 'balance', 'transfer', 'payment', 'swift', 
                     'settlement', 'clearing', 'reconciliation', 'audit']
    return f"{event}: {kwargs.get('user', 'unknown')} performed {random.choice(banking_terms)} operation"

def generate_geo():
    """Generate realistic geo-location"""
    locations = [
        ('New York', 'US'), ('London', 'GB'), ('Mumbai', 'IN'), ('Singapore', 'SG'),
        ('Frankfurt', 'DE'), ('Tokyo', 'JP'), ('Hong Kong', 'HK'), ('Dubai', 'AE'),
        ('Toronto', 'CA'), ('Sydney', 'AU'), ('Zurich', 'CH'), ('Paris', 'FR'),
    ]
    
    city, country = random.choice(locations)
    
    if random.random() < 0.3:
        return f"{city}, {country}"
    elif random.random() < 0.5:
        return country
    else:
        return city

def generate_notes(event_type, severity, attempts=None):
    """Generate dynamic threat tags"""
    prefix = random.choice(['GT', 'SEC', 'THREAT', 'ANOMALY', 'COMPLIANCE', 'AUDIT'])
    tags = []
    
    if '4625' in str(event_type) or (attempts and attempts > 5):
        tags.append('BRUTE_FORCE' if attempts and attempts > 10 else 'SINGLE_FAIL')
    elif 'NET_CONN' in str(event_type):
        tags.append('DATA_XFER')
    elif severity == 'CRITICAL':
        tags.append('HIGH_RISK')
    elif severity == 'HIGH':
        tags.append('SUSPICIOUS')
    else:
        tags.append('BASELINE')
    
    if severity in ['CRITICAL', 'HIGH']:
        tags.append('URGENT')
    
    tag_id = fake.word().upper()[:4]
    
    if tags:
        return f"{prefix}_{'_'.join(tags)}_{tag_id}"
    return f"{prefix}_{tag_id}"

def generate_robust_security_logs(num_rows):
    """Main function to generate security logs"""
    
    data = []
    current_ts = START_DATE
    duplicate_buffer = []
    
    for row_id in range(num_rows):
        # Timestamp
        if random.random() > NOISE_CONFIG['invalid_timestamp_rate']:
            current_ts += timedelta(seconds=random.randint(1, 900))
            ts = current_ts.isoformat() + 'Z'
        else:
            invalid_formats = [
                f"{random.randint(2020, 2025)}-{random.randint(1, 13)}-{random.randint(1, 35)}T{random.randint(0, 25)}:{random.randint(0, 61)}:{random.randint(0, 61)}Z",
                f"{random.randint(1, 31)}/{random.randint(1, 12)}/{random.randint(2020, 2025)}",
                "invalid-timestamp",
                ""
            ]
            ts = random.choice(invalid_formats)
        
        source = random.choice(LOG_SOURCES)
        possible_events = EVENT_MAPPINGS.get(source, ['unknown'])
        event = random.choice(possible_events)
        
        host = generate_hostname()
        user = generate_username()
        ip = generate_ip()
        proc = generate_process_name()
        dst = generate_destination() if random.random() < 0.4 else ''
        
        attempts = None
        if '4625' in str(event) or 'LOGIN_FAIL' in str(event) or 'SignIn' in str(event):
            attempts = random.randint(1, 100)
        
        # Severity
        if attempts and attempts > 15:
            severity = 'CRITICAL'
        else:
            severity_weights = [0.55, 0.25, 0.12, 0.06, 0.02]
            severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN']
            severity = np.random.choice(severities, p=severity_weights)
        
        file_path = generate_file_path() if random.random() < 0.35 else ''
        
        message = generate_message(
            event, source,
            user=user, 
            ip=ip, 
            proc=proc, 
            cmd=generate_command_line(proc),
            dest=dst, 
            target=generate_process_name(),
            risk=random.choice(['none', 'low', 'medium', 'high']),
            action=random.choice(['create', 'modify', 'delete', 'read'])
        )
        
        geo = generate_geo() if random.random() < 0.6 else ''
        notes = generate_notes(event, severity, attempts)
        
        # Add noise
        if random.random() < NOISE_CONFIG['missing_rate']:
            missing_field = random.choice(['host', 'user', 'ip', 'proc', 'message', 'geo'])
            if missing_field == 'host':
                host = ''
            elif missing_field == 'user':
                user = ''
            elif missing_field == 'ip':
                ip = ''
            elif missing_field == 'proc':
                proc = ''
            elif missing_field == 'message':
                message = ''
            elif missing_field == 'geo':
                geo = ''
        
        if attempts and random.random() < NOISE_CONFIG['outlier_rate']:
            attempts = attempts * random.randint(5, 20)
        
        if random.random() < NOISE_CONFIG['encoding_errors']:
            user = user.encode('ascii', 'ignore').decode() + '\x00\x01'
            message = message + '�'
        
        row = [
            ts, host, user, event, attempts, severity, ip, file_path,
            proc, dst, message, geo, notes, source
        ]
        
        data.append(row)
        
        # Generate duplicates
        if random.random() < NOISE_CONFIG['duplicate_rate'] and row_id > 0:
            duplicate_buffer.append(row)
            if len(duplicate_buffer) > 5:
                duplicate_buffer.pop(0)
            if duplicate_buffer:
                data.append(duplicate_buffer[-1].copy())
    
    df = pd.DataFrame(data, columns=[
        'ts', 'host', 'user', 'event', 'attempts', 'severity',
        'ip', 'file', 'proc', 'dst', 'message', 'geo', 'notes', 'source'
    ])
    
    return df

# Main execution
print("="*70)
print("SECURITY LOG DATASET GENERATOR")
print("="*70)
print(f"\nTarget rows: {NUM_ROWS:,}")
print("Generating robust security log dataset...")

# Generate the dataset
df = generate_robust_security_logs(NUM_ROWS)

# Add additional columns for ML
print("Adding ML-ready columns...")
df['ts_clean'] = pd.to_datetime(df['ts'], errors='coerce')
df['hour'] = df['ts_clean'].dt.hour.fillna(0).astype(int)
df['day_of_week'] = df['ts_clean'].dt.dayofweek.fillna(0).astype(int)
df['month'] = df['ts_clean'].dt.month.fillna(0).astype(int)
df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
df['is_off_hours'] = ((df['hour'] < 8) | (df['hour'] > 18)).astype(int)
df['message_length'] = df['message'].str.len().fillna(0).astype(int)
df['has_ip'] = df['message'].str.contains(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', na=False).astype(int)
df['has_error'] = df['message'].str.contains('error|fail|denied', case=False, na=False).astype(int)
df['attempts'].fillna(0, inplace=True)
df['has_attempts'] = (df['attempts'] > 0).astype(int)
df['is_suspicious'] = ((df['severity'].isin(['CRITICAL', 'HIGH'])) | (df['attempts'] > 10)).astype(int)
df['is_high_risk'] = ((df['severity'].isin(['CRITICAL', 'HIGH'])) | (df['attempts'] > 10) | (df['is_suspicious'] == 1)).astype(int)

# Remove temporary column
df.drop('ts_clean', axis=1, inplace=True)

# Save to CSV
output_file = f'synthetic_bank_logs_{NUM_ROWS}_robust.csv'
print(f"\nSaving to {output_file}...")
df.to_csv(output_file, index=False)

# Generate summary
print("\n" + "="*70)
print("DATASET GENERATION COMPLETE!")
print("="*70)
print(f"\n✅ Generated {len(df):,} rows")
print(f"✅ File saved: {output_file}")
print(f"✅ File size: {len(df.to_csv(index=False)) / 1024 / 1024:.2f} MB")

print("\n📊 Dataset Statistics:")
print(f"  - Columns: {len(df.columns)}")
print(f"  - Log sources: {df['source'].nunique()}")
print(f"  - Unique events: {df['event'].nunique()}")
print(f"  - Unique hosts: {df['host'].nunique():,}")
print(f"  - Unique users: {df['user'].nunique():,}")

print("\n⚠️ Data Quality:")
print(f"  - Missing/empty fields: {(df == '').sum().sum():,}")
print(f"  - Invalid timestamps: {pd.to_datetime(df['ts'], errors='coerce').isna().sum():,}")
print(f"  - High-risk events: {df['is_high_risk'].sum():,} ({df['is_high_risk'].mean()*100:.1f}%)")

print("\n📈 Severity Distribution:")
print(df['severity'].value_counts())

print("\n🖥️ Top 10 Log Sources:")
print(df['source'].value_counts().head(10))

print("\n👤 Top 10 Users:")
print(df['user'].value_counts().head(10))

print("\n" + "="*70)
print("✅ DONE! Ready for ML training")
print("="*70)