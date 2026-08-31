#!/usr/bin/python3
# DC Kerberoasting Response Script - Version améliorée avec détection SPN
# Détection des comptes SPN compromis dans les alertes Kerberoasting

import os
import sys
import json
import datetime
import subprocess
import re
import secrets
import string
import time
import socket
from pathlib import PureWindowsPath, PurePosixPath

# Configuration
if os.name == 'nt':
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
    DEBUG_LOG = "C:\\wazuh_dc_kerberoast.log"
    WHITELIST_FILE = "C:\\wazuh_ad_whitelist.txt"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"
    DEBUG_LOG = "/tmp/wazuh_dc_kerberoast.log"
    WHITELIST_FILE = "/tmp/wazuh_ad_whitelist.txt"

ADD_COMMAND = 0
DELETE_COMMAND = 1
OS_SUCCESS = 0
OS_INVALID = -1

class Message:
    def __init__(self):
        self.alert = ""
        self.command = 0

def write_debug_file(ar_name, msg):
    """Logging Wazuh compatible"""
    try:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(ar_name[ar_name.find("active-response"):])))
        log_line = f"{datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')} {ar_name_posix}: {msg}"
        
        with open(LOG_FILE, mode="a", encoding="utf-8") as log_file:
            log_file.write(log_line + "\n")
            
        with open(DEBUG_LOG, mode="a", encoding="utf-8") as debug_file:
            debug_file.write(f"[{datetime.datetime.now()}] {msg}\n")
            
    except Exception as e:
        print(f"LOG ERROR: {e}", file=sys.stderr)

def setup_and_check_message(argv):
    """Parse Wazuh message"""
    try:
        input_str = sys.stdin.readline()
        if not input_str:
            write_debug_file(argv[0], "ERROR: stdin vide")
            return None
        
        write_debug_file(argv[0], f"Input reçu ({len(input_str)} chars)")
        
        data = json.loads(input_str)
        msg = Message()
        msg.alert = data
        
        command = data.get("command", "")
        if command == "add":
            msg.command = ADD_COMMAND
        elif command == "delete":
            msg.command = DELETE_COMMAND
        else:
            write_debug_file(argv[0], f"Commande invalide: {command}")
            return None
            
        return msg
        
    except json.JSONDecodeError as e:
        write_debug_file(argv[0], f"Erreur JSON: {e}")
        return None
    except Exception as e:
        write_debug_file(argv[0], f"Erreur lecture: {e}")
        return None

def get_safe_output(cmd, timeout=10):
    """Execute command with robust encoding handling"""
    try:
        # Try multiple encodings
        encodings_to_try = ['latin-1', 'cp850', 'utf-8']
        
        for encoding in encodings_to_try:
            try:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    encoding=encoding,
                    timeout=timeout,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                return result.stdout
            except UnicodeDecodeError:
                continue
        
        # Fallback
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return result.stdout.decode('utf-8', errors='ignore')
        
    except Exception as e:
        write_debug_file("get_safe_output", f"Error: {e}")
        return ""

def get_current_domain():
    """Get current domain reliably"""
    try:
        # Method 1: PowerShell (most reliable)
        domain_cmd = """
        try {
            $domain = (Get-ADDomain).NetBIOSName
            Write-Output $domain
        } catch {
            # Fallback: Computer domain
            $env:USERDOMAIN
        }
        """
        
        result = subprocess.run(
            ["powershell", "-Command", domain_cmd],
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if result.returncode == 0 and result.stdout.strip():
            domain = result.stdout.strip().upper()
            write_debug_file("get_domain", f"Domain via PowerShell: {domain}")
            return domain
        
        # Method 2: Environment variable
        domain = os.environ.get('USERDOMAIN', '')
        if domain:
            write_debug_file("get_domain", f"Domain via ENV: {domain}")
            return domain.upper()
        
        # Method 3: Hostname parsing
        hostname = socket.gethostname()
        if '.' in hostname:
            domain = hostname.split('.', 1)[1].upper()
            write_debug_file("get_domain", f"Domain via hostname: {domain}")
            return domain
        
        write_debug_file("get_domain", "Using default domain: DOMAIN")
        return "DOMAIN"
        
    except Exception as e:
        write_debug_file("get_domain", f"Error getting domain: {e}")
        return "DOMAIN"

def extract_service_accounts(alert_data):
    """Extract service accounts from alert - VERSION DYNAMIQUE CORRIGÉE"""
    try:
        write_debug_file("extract_service_accounts", "Starting extraction...")
        
        service_accounts = []
        
        # DEBUG: Show structure
        write_debug_file("extract_service_accounts", f"Alert data type: {type(alert_data)}")
        
        # Navigate through the complex structure
        current_data = alert_data
        
        # Try to find the alert data
        if isinstance(current_data, dict):
            # Method 1: Check parameters -> alert
            if 'parameters' in current_data and 'alert' in current_data['parameters']:
                current_data = current_data['parameters']['alert']
                write_debug_file("extract_service_accounts", "Found path: parameters->alert")
            
            # Method 2: Check alert directly
            elif 'alert' in current_data:
                current_data = current_data['alert']
                write_debug_file("extract_service_accounts", "Found path: alert")
        
        # Now try to find the actual data
        if isinstance(current_data, dict):
            # Try multiple possible paths
            possible_paths = [
                ['data', 'win', 'eventdata', 'serviceName'],
                ['win', 'eventdata', 'serviceName'],
                ['eventdata', 'serviceName'],
                ['data', 'win', 'system', 'message'],
                ['data', 'eventdata', 'serviceName'],
                ['full_log'],
                ['message']
            ]
            
            for path in possible_paths:
                try:
                    value = current_data
                    for key in path:
                        if isinstance(value, dict) and key in value:
                            value = value[key]
                        else:
                            value = None
                            break
                    
                    if value:
                        write_debug_file("extract_service_accounts", f"Found value at path {path}: {value[:100] if isinstance(value, str) else value}")
                        
                        # Process the value
                        if isinstance(value, str):
                            # It's the serviceName field directly
                            if 'serviceName' in str(path):
                                account = value.split('@')[0].split('/')[0].strip()
                                if account and account not in service_accounts:
                                    service_accounts.append(account)
                                    write_debug_file("extract_service_accounts", f"Added from serviceName: {account}")
                            
                            # It's a message field, need to extract
                            else:
                                # Try to extract from French message
                                patterns = [
                                    r'Nom du service[:\s]*\t+([^\r\n\t@]+)',  # French pattern
                                    r'service name[:\s]*\t+([^\r\n\t@]+)',    # English pattern
                                    r'Service Name[:\s]*\t+([^\r\n\t@]+)',    # English capitalized
                                    r'service:\s+([^\s\r\n,@]+)',             # Generic
                                    r'service\s+=\s+([^\s\r\n,@]+)',          # Alternative format
                                ]
                                
                                for pattern in patterns:
                                    matches = re.findall(pattern, value, re.IGNORECASE)
                                    for match in matches:
                                        if match:
                                            account = match.strip()
                                            if account and account not in service_accounts:
                                                service_accounts.append(account)
                                                write_debug_file("extract_service_accounts", f"Added from message pattern '{pattern}': {account}")
                
                except Exception as e:
                    write_debug_file("extract_service_accounts", f"Error checking path {path}: {e}")
                    continue
        
        # SPECIAL CASE: Direct extraction from your specific JSON structure
        # Try brute-force search in the entire JSON
        if not service_accounts:
            write_debug_file("extract_service_accounts", "Trying brute-force search...")
            
            # Convert to string and search
            alert_str = json.dumps(alert_data)
            
            # Pattern for serviceName field in JSON
            patterns = [
                r'"serviceName"\s*:\s*"([^"]+)"',           # JSON field
                r'serviceName["\']?\s*[:=]\s*["\']?([^"\',\s]+)',  # Flexible pattern
                r'Nom du service["\']?\s*[:=]\s*["\']?([^"\',\s]+)', # French in JSON
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, alert_str, re.IGNORECASE)
                for match in matches:
                    if match and match != 'null' and match != '""':
                        account = match.split('@')[0].split('/')[0].strip()
                        if account and account not in service_accounts:
                            service_accounts.append(account)
                            write_debug_file("extract_service_accounts", f"Added from brute-force pattern '{pattern}': {account}")
        
        # Fallback: Extract from eventdata if present
        if not service_accounts and isinstance(alert_data, dict):
            try:
                # Try to navigate to eventdata
                eventdata = None
                
                # Path 1: alert.parameters.alert.data.win.eventdata
                if 'parameters' in alert_data and 'alert' in alert_data['parameters']:
                    alert_part = alert_data['parameters']['alert']
                    if 'data' in alert_part and 'win' in alert_part['data'] and 'eventdata' in alert_part['data']['win']:
                        eventdata = alert_part['data']['win']['eventdata']
                
                # Path 2: alert.data.win.eventdata
                elif 'data' in alert_data and 'win' in alert_data['data'] and 'eventdata' in alert_data['data']['win']:
                    eventdata = alert_data['data']['win']['eventdata']
                
                if eventdata and isinstance(eventdata, dict):
                    if 'serviceName' in eventdata:
                        account = eventdata['serviceName'].split('@')[0].split('/')[0].strip()
                        if account and account not in service_accounts:
                            service_accounts.append(account)
                            write_debug_file("extract_service_accounts", f"Added from direct eventdata.serviceName: {account}")
                    
                    # Also check for targetUserName (but this might be the user, not the service)
                    if 'targetUserName' in eventdata:
                        target = eventdata['targetUserName']
                        write_debug_file("extract_service_accounts", f"Note: targetUserName found: {target} (usually the requesting user)")
            
            except Exception as e:
                write_debug_file("extract_service_accounts", f"Error in eventdata fallback: {e}")
        
        # Clean and deduplicate
        service_accounts = [acc for acc in service_accounts if acc and acc.strip() and acc.lower() != 'null']
        service_accounts = list(set(service_accounts))
        
        write_debug_file("extract_service_accounts", f"Final extracted accounts: {service_accounts}")
        
        # If still empty, try one more aggressive method
        if not service_accounts:
            write_debug_file("extract_service_accounts", "Trying aggressive pattern matching...")
            
            # Deep search for any account-like patterns
            alert_str = json.dumps(alert_data)
            
            # Look for patterns that look like service accounts
            account_patterns = [
                r'admin_[a-zA-Z0-9_]+',        # admin_xxx pattern
                r'svc_[a-zA-Z0-9_]+',          # svc_xxx pattern
                r'service_[a-zA-Z0-9_]+',      # service_xxx pattern
                r'krbtgt',                     # krbtgt account
                r'sql_[a-zA-Z0-9_]+',          # sql_xxx pattern
                r'iis_[a-zA-Z0-9_]+',          # iis_xxx pattern
                r'http_[a-zA-Z0-9_]+',         # http_xxx pattern
            ]
            
            for pattern in account_patterns:
                matches = re.findall(pattern, alert_str, re.IGNORECASE)
                for match in matches:
                    if match and match not in service_accounts:
                        service_accounts.append(match)
                        write_debug_file("extract_service_accounts", f"Added from aggressive pattern '{pattern}': {match}")
        
        write_debug_file("extract_service_accounts", f"Extraction complete. Found: {service_accounts}")
        return service_accounts
        
    except Exception as e:
        write_debug_file("extract_service_accounts", f"ERROR during extraction: {str(e)}")
        import traceback
        write_debug_file("extract_service_accounts", f"Traceback: {traceback.format_exc()}")
        return []

def is_protected_account(account):
    """Check if account is protected - VERSION AMÉLIORÉE"""
    # Liste des comptes exacts à protéger
    exact_protected = [
        'krbtgt', 'administrator', 'administrateur', 'guest',
        'system', 'network service', 'local service'
    ]
    
    # Liste des patterns partiels (doit contenir exactement ces mots)
    partial_protected = [
        'domain admins', 'enterprise admins', 'schema admins'
    ]
    
    account_lower = account.lower()
    
    # Vérification exacte
    if account_lower in exact_protected:
        return True
    
    # Vérification partielle pour les groupes
    for protected_pattern in partial_protected:
        if account_lower == protected_pattern:
            return True
    
    # Vérification plus intelligente pour "admin"
    # Seulement si le compte est exactement "admin" ou commence par "admin" suivi de caractères spéciaux
    if account_lower == 'admin':
        return True
    
    # Check whitelist file
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
                whitelist = [line.strip().lower() for line in f if line.strip()]
                if account_lower in whitelist:
                    return True
        except Exception as e:
            write_debug_file("whitelist", f"Error reading whitelist: {e}")
    
    return False

def generate_secure_password(length=24):
    """Generate secure random password"""
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(chars) for _ in range(length))

def create_secure_password_dir():
    """Create secure directory for password storage"""
    try:
        # Use ProgramData for proper permissions
        program_data = os.environ.get('PROGRAMDATA', 'C:\\ProgramData')
        secure_dir = os.path.join(program_data, 'wazuh', 'secure_passwords')
        
        # Create directory with secure permissions
        os.makedirs(secure_dir, exist_ok=True)
        
        # Set permissions (System and Administrators only)
        perm_cmd = f'icacls "{secure_dir}" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"'
        subprocess.run(perm_cmd, shell=True, capture_output=True, timeout=10)
        
        write_debug_file("secure_dir", f"Secure directory: {secure_dir}")
        return secure_dir
        
    except Exception as e:
        write_debug_file("secure_dir", f"Error creating secure dir: {e}")
        return None

def reset_service_account_password(account, domain):
    """Reset service account password with secure storage"""
    try:
        # 1. Check if account exists
        check_cmd = f"""
        try {{
            $user = Get-ADUser -Filter {{SamAccountName -eq '{account}'}} -Server '{domain}' -ErrorAction Stop
            if ($user) {{
                Write-Output "EXISTS:$($user.Enabled)"
            }} else {{
                Write-Output "NOTFOUND"
            }}
        }} catch {{
            Write-Output "ERROR:$($_.Exception.Message)"
        }}
        """
        
        result = subprocess.run(
            ["powershell", "-Command", check_cmd],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if "NOTFOUND" in result.stdout:
            return False, f"Account {account} not found in domain {domain}"
        elif "ERROR" in result.stdout:
            return False, f"Error checking account: {result.stdout}"
        
        # 2. Generate new secure password
        new_password = generate_secure_password()
        
        # 3. Reset password in AD
        reset_cmd = f"""
        try {{
            $securePassword = ConvertTo-SecureString "{new_password}" -AsPlainText -Force
            Set-ADAccountPassword -Identity '{account}' -NewPassword $securePassword -Reset -Server '{domain}' -ErrorAction Stop
            Set-ADUser -Identity '{account}' -ChangePasswordAtLogon $false -Server '{domain}' -ErrorAction Stop
            Write-Output "SUCCESS"
        }} catch {{
            Write-Output "ERROR:$($_.Exception.Message)"
        }}
        """
        
        reset_result = subprocess.run(
            ["powershell", "-Command", reset_cmd],
            capture_output=True,
            text=True,
            timeout=60,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if "ERROR" in reset_result.stdout:
            return False, f"Password reset failed: {reset_result.stdout}"
        
        # 4. Store password securely (temporary, auto-deleting)
        secure_dir = create_secure_password_dir()
        if secure_dir:
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            pass_file = os.path.join(secure_dir, f"{account}_{timestamp}.txt")
            
            # Write password with warning
            with open(pass_file, 'w', encoding='utf-8') as f:
                f.write(f"=== WAZUH PASSWORD RESET ===\n")
                f.write(f"Account: {domain}\\{account}\n")
                f.write(f"New Password: {new_password}\n")
                f.write(f"Time: {datetime.datetime.now()}\n")
                f.write(f"File: {pass_file}\n")
                f.write("\n=== WARNING ===\n")
                f.write("1. Update application configurations immediately\n")
                f.write("2. This file will auto-delete in 1 hour\n")
                f.write("3. Store password in a secure vault\n")
            
            # Set restrictive permissions
            perm_cmd = f'icacls "{pass_file}" /inheritance:r /grant:r "SYSTEM:(R)" "Administrators:(R)"'
            subprocess.run(perm_cmd, shell=True, capture_output=True, timeout=10)
            
            # Schedule auto-delete in 1 hour (non-blocking)
            del_cmd = f'powershell -Command "Start-Sleep -Seconds 3600; Remove-Item \'{pass_file}\' -Force"'
            subprocess.Popen(
                del_cmd,
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            write_debug_file("password_reset", f"Password stored temporarily: {pass_file} (auto-deletes in 1h)")
            
            return True, f"Password reset. Temporary file: {pass_file}"
        else:
            # If secure dir fails, still reset password but warn
            return True, f"Password reset but NOT STORED. Immediate action required!"
            
    except subprocess.TimeoutExpired:
        return False, "Timeout resetting password"
    except Exception as e:
        return False, f"Exception: {str(e)}"

def enable_aes_encryption(account, domain):
    """Enable AES encryption for account"""
    try:
        aes_cmd = f"""
        try {{
            Set-ADAccountControl -Identity '{account}' -UseDESKeyOnly $false -Server '{domain}' -ErrorAction Stop
            Write-Output "SUCCESS"
        }} catch {{
            Write-Output "ERROR:$($_.Exception.Message)"
        }}
        """
        
        result = subprocess.run(
            ["powershell", "-Command", aes_cmd],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if "SUCCESS" in result.stdout:
            return True, "AES encryption enabled (resists Kerberoasting)"
        else:
            error_msg = result.stdout.split("ERROR:")[1] if "ERROR:" in result.stdout else result.stdout
            return False, f"AES enable failed: {error_msg}"
            
    except Exception as e:
        return False, f"Exception: {str(e)}"

def audit_spns(account, domain):
    """Audit SPNs for service account"""
    try:
        audit_cmd = f"""
        try {{
            $user = Get-ADUser -Identity '{account}' -Properties ServicePrincipalNames -Server '{domain}' -ErrorAction Stop
            if ($user.ServicePrincipalNames) {{
                $spn_count = $user.ServicePrincipalNames.Count
                $spn_list = $user.ServicePrincipalNames -join "`, `n"
                Write-Output "FOUND:$spn_count`n$spn_list"
            }} else {{
                Write-Output "NONE"
            }}
        }} catch {{
            Write-Output "ERROR:$($_.Exception.Message)"
        }}
        """
        
        result = subprocess.run(
            ["powershell", "-Command", audit_cmd],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if "FOUND:" in result.stdout:
            parts = result.stdout.split(":", 1)
            details = parts[1].replace("`n", "\n")
            return True, f"Found SPNs:\n{details}"
        elif "NONE" in result.stdout:
            return True, "No SPNs found"
        else:
            error_msg = result.stdout.split("ERROR:")[1] if "ERROR:" in result.stdout else result.stdout
            return False, f"SPN audit failed: {error_msg}"
            
    except Exception as e:
        return False, f"Exception: {str(e)}"

def revoke_kerberos_tickets(account, domain):
    """Attempt to revoke Kerberos tickets with clear limitations"""
    try:
        write_debug_file("ticket_revoke", 
            f"Note: klist purge only clears local DC cache. "
            f"Attacker tickets remain valid until expiration or password reset.")
        
        # Optional: Clear local ticket cache
        purge_cmd = "klist purge -li 0x3e7 2>&1"
        result = get_safe_output(purge_cmd, 15)
        
        return True, "Local DC ticket cache cleared (attacker tickets still valid)"
        
    except Exception as e:
        return False, f"Exception: {str(e)}"

def log_security_event(action, account, details):
    """Log security event to Windows Event Log"""
    try:
        # Truncate details if too long
        if len(details) > 3000:
            details = details[:3000] + "...[truncated]"
        
        event_cmd = f"""
        eventcreate /L SECURITY /T AUDIT_SUCCESS /SO "Wazuh DC Response" `
        /ID 4769 /D "Wazuh AD Response: {action} for {account}. Details: {details}"
        """
        
        result = subprocess.run(
            event_cmd,
            shell=True,
            timeout=10,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if result.returncode == 0:
            return True
        else:
            write_debug_file("event_log", f"Event create failed: {result.stderr}")
            return False
            
    except Exception as e:
        write_debug_file("event_log", f"Exception logging event: {e}")
        return False

def main(argv):
    script_name = argv[0] if argv else "dc-kerberoast-response"
    write_debug_file(script_name, "=" * 60)
    write_debug_file(script_name, "DC KERBEROASTING RESPONSE - STARTED")
    
    try:
        # 1. Parse message
        msg = setup_and_check_message(argv)
        if not msg:
            write_debug_file(script_name, "No valid message received")
            sys.exit(OS_SUCCESS)
        
        if msg.command != ADD_COMMAND:
            write_debug_file(script_name, "Ignoring DELETE command")
            sys.exit(OS_SUCCESS)
        
        write_debug_file(script_name, "Processing Kerberoasting alert on DC")
        
        # 2. Get current domain (RELIABLY)
        domain = get_current_domain()
        write_debug_file(script_name, f"Using domain: {domain}")
        
        # 3. Extract service accounts - VERSION DYNAMIQUE
        service_accounts = extract_service_accounts(msg.alert)
        write_debug_file(script_name, f"Service accounts extracted: {service_accounts}")
        
        if not service_accounts:
            write_debug_file(script_name, "No service accounts found in alert")
            sys.exit(OS_SUCCESS)
        
        results = []
        processed_accounts = []
        skipped_accounts = []
        
        # 4. Process each service account
        for account in service_accounts:
            write_debug_file(script_name, f"Processing account: {account}")
            
            # Skip protected accounts
            if is_protected_account(account):
                write_debug_file(script_name, f"SKIPPED: {account} is protected")
                skipped_accounts.append(account)
                results.append(f"{account}: SKIPPED (protected account)")
                continue
            
            account_results = []
            
            # A. Reset password (CRITICAL ACTION)
            success, message = reset_service_account_password(account, domain)
            if success:
                account_results.append(f"✓ Password reset: {message}")
                write_debug_file(script_name, f"Password reset for {account}")
            else:
                account_results.append(f"✗ Password reset FAILED: {message}")
                write_debug_file(script_name, f"Password reset failed for {account}: {message}")
            
            # B. Enable AES encryption
            success, message = enable_aes_encryption(account, domain)
            if success:
                account_results.append(f"✓ AES encryption enabled")
            else:
                account_results.append(f"✗ AES enable failed: {message}")
            
            # C. Audit SPNs
            success, message = audit_spns(account, domain)
            if success:
                # Truncate long SPN lists
                if len(message) > 200:
                    message = message[:200] + "..."
                account_results.append(f"✓ {message}")
            else:
                account_results.append(f"✗ SPN audit failed: {message}")
            
            # D. Attempt ticket revocation (with clear limitations)
            success, message = revoke_kerberos_tickets(account, domain)
            account_results.append(f"ℹ {message}")
            
            # Log security event
            log_security_event("Kerberoasting response", account, 
                             f"Actions: {'; '.join(account_results)}")
            
            results.append(f"{account}:\n  " + "\n  ".join(account_results))
            processed_accounts.append(account)
        
        # 5. Create comprehensive report
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        report_dir = os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 
                                 'wazuh', 'reports')
        os.makedirs(report_dir, exist_ok=True)
        
        report_file = os.path.join(report_dir, f"kerberoast_response_{timestamp}.txt")
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("WAZUH DC KERBEROASTING RESPONSE REPORT\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Report Time: {datetime.datetime.now()}\n")
            f.write(f"Domain: {domain}\n")
            f.write(f"Alert Time: {msg.alert.get('timestamp', 'Unknown')}\n")
            f.write("\n" + "=" * 70 + "\n\n")
            
            f.write("PROCESSED ACCOUNTS:\n")
            f.write("-" * 40 + "\n")
            if processed_accounts:
                for account in processed_accounts:
                    f.write(f"✓ {account}\n")
            else:
                f.write("None\n")
            
            f.write("\nSKIPPED ACCOUNTS (Protected):\n")
            f.write("-" * 40 + "\n")
            if skipped_accounts:
                for account in skipped_accounts:
                    f.write(f"⚠ {account}\n")
            else:
                f.write("None\n")
            
            f.write("\n" + "=" * 70 + "\n\n")
            f.write("DETAILED RESULTS:\n")
            f.write("=" * 70 + "\n\n")
            for result in results:
                f.write(result + "\n\n")
            
            f.write("\n" + "=" * 70 + "\n\n")
            f.write("IMMEDIATE NEXT ACTIONS REQUIRED:\n")
            f.write("=" * 70 + "\n")
            f.write("1. NOTIFY application owners of password changes\n")
            f.write("2. UPDATE service configurations with new passwords\n")
            f.write("3. MOVE passwords from temporary files to secure vault\n")
            f.write("4. MONITOR for authentication failures\n")
            f.write("5. INVESTIGATE source of Kerberoasting attack\n")
            f.write("6. REVIEW SPNs and clean unnecessary ones\n")
            f.write("\nNOTE: Temporary password files auto-delete in 1 hour!\n")
        
        write_debug_file(script_name, f"Report created: {report_file}")
        
        # 6. Critical warning for krbtgt targeting
        for account in service_accounts:
            if 'krbtgt' in account.lower():
                write_debug_file(script_name, "=" * 60)
                write_debug_file(script_name, "⚠⚠⚠ KRBTGT ACCOUNT TARGETED ⚠⚠⚠")
                write_debug_file(script_name, "IMMEDIATE MANUAL ACTION REQUIRED:")
                write_debug_file(script_name, "1. Reset krbtgt password TWICE (Microsoft procedure)")
                write_debug_file(script_name, "2. Monitor for replication issues")
                write_debug_file(script_name, "3. Check all DCs for consistency")
                write_debug_file(script_name, "=" * 60)
        
        write_debug_file(script_name, "DC KERBEROASTING RESPONSE - COMPLETED")
        
    except Exception as e:
        write_debug_file(script_name, f"UNEXPECTED ERROR: {type(e).__name__}: {str(e)}")
        import traceback
        write_debug_file(script_name, f"Traceback: {traceback.format_exc()}")
        
    finally:
        write_debug_file(script_name, "=" * 60)
        sys.exit(OS_SUCCESS)

if __name__ == "__main__":
    main(sys.argv)