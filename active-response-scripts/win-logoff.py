import os
import sys
import json
import datetime
import subprocess
import re
from pathlib import PureWindowsPath, PurePosixPath

# Configuration des logs
if os.name == 'nt':
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
    DEBUG_LOG = "C:\\wazuh_debug.log"  # Log additionnel pour debug
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"
    DEBUG_LOG = "/tmp/wazuh_debug.log"

ADD_COMMAND = 0
DELETE_COMMAND = 1
OS_SUCCESS = 0
OS_INVALID = -1

class Message:
    def __init__(self):
        self.alert = ""
        self.command = 0

def write_debug_file(ar_name, msg):
    """Log dans le fichier Wazuh et dans un fichier debug local"""
    try:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(ar_name[ar_name.find("active-response"):])))
        log_line = f"{datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')} {ar_name_posix}: {msg}"
        
        with open(LOG_FILE, mode="a", encoding="utf-8") as log_file:
            log_file.write(log_line + "\n")
            
        with open(DEBUG_LOG, mode="a", encoding="utf-8") as debug_file:
            debug_file.write(f"[{datetime.datetime.now()}] {ar_name}: {msg}\n")
            
    except Exception as e:
        print(f"LOG ERROR: {e}", file=sys.stderr)

def setup_and_check_message(argv):
    """Lit et parse le message Wazuh de manière instantanée"""
    try:
        # CORRECTION ICI : readline() au lieu de read() pour éviter l'attente EOF
        input_str = sys.stdin.readline()
        if not input_str:
            write_debug_file(argv[0], "ERROR: stdin vide")
            return None
        
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
        write_debug_file(argv[0], f"Erreur lecture stdin: {e}")
        return None

def extract_user_recursive(d, depth=0):
    """Extrait le nom d'utilisateur de manière récursive"""
    if depth > 4 or not isinstance(d, dict):
        return None
    
    user_fields = ['subjectUserName', 'targetUserName', 'sourceUser', 
                   'srcuser', 'dstuser', 'accountName', 'user',
                   'SubjectUserName', 'TargetUserName', 'SourceUserName']
    
    for field in user_fields:
        val = d.get(field)
        if val and str(val).strip() not in ['-', 'N/A', 'NULL', '', 'SYSTEM']:
            username = str(val).strip()
            if '\\' in username:
                username = username.split('\\')[-1]
            return username
    
    for key, value in d.items():
        if isinstance(value, dict):
            res = extract_user_recursive(value, depth + 1)
            if res: 
                return res
    
    return None

def is_dangerous_account(username):
    """Vérifie si c'est un compte système critique"""
    if not username:
        return True
    
    dangerous = [
        'SYSTEM', 'LOCAL SYSTEM', 'LOCALSYSTEM',
        'ADMINISTRATOR', 'ADMIN', 
        'LOCAL SERVICE', 'NETWORK SERVICE',
        'SERVICE', 'SYSTÈME', 'LOCAL'
    ]
    
    username_lower = username.lower()
    return any(danger.lower() == username_lower for danger in dangerous)

def get_safe_output(cmd):
    """Exécute une commande avec gestion robuste de l'encodage"""
    try:
        encodings_to_try = ['cp850', 'cp437', 'latin-1', 'utf-8', 'cp1252']
        
        for encoding in encodings_to_try:
            try:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    encoding=encoding,
                    timeout=10,
                    creationflags=0x08000000 # CREATE_NO_WINDOW
                )
                
                if result.returncode == 0:
                    return result.stdout
                    
            except UnicodeDecodeError:
                continue
        
        return ""
            
    except Exception as e:
        return ""

def find_user_session(username):
    """Trouve la session d'un utilisateur"""
    if not username:
        return None
    
    output = get_safe_output(f'query session "{username}"')
    
    if output and username.lower() in output.lower():
        for line in output.split('\n'):
            if username.lower() in line.lower() and 'services' not in line.lower():
                parts = line.split()
                for i, part in enumerate(parts):
                    if part.lower() == username.lower() and i + 1 < len(parts):
                        if parts[i + 1].isdigit():
                            return parts[i + 1]
    
    output = get_safe_output('qwinsta')
    if output:
        pattern = rf'\s+{re.escape(username)}\s+(\d+)\s+\w+\s*$'
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return None

def disconnect_session(session_id, username):
    """Déconnecte une session"""
    if not session_id or session_id == "0":
        return False
    
    try:
        # 0x08000000 évite l'ouverture d'une fenêtre CMD
        result = subprocess.run(
            f"logoff {session_id}",
            shell=True,
            capture_output=True,
            text=True,
            encoding='latin-1',
            timeout=15,
            creationflags=0x08000000
        )
        
        if result.returncode == 0:
            write_debug_file("disconnect", f"SUCCESS: Session {session_id} disconnected")
            return True
        else:
            return False
                
    except Exception as e:
        write_debug_file("disconnect", f"Exception: {e}")
        return False

def main(argv):
    script_name = argv[0] if argv else "win-logoff"
    
    try:
        msg = setup_and_check_message(argv)
        if not msg:
            sys.exit(OS_SUCCESS)
        
        if msg.command != ADD_COMMAND:
            sys.exit(OS_SUCCESS)
        
        alert_root = msg.alert.get('parameters', {}).get('alert', msg.alert.get('alert', msg.alert))
        username = extract_user_recursive(alert_root)
        
        if not username or is_dangerous_account(username):
            write_debug_file(script_name, f"Aborted: User {username} is system or not found")
            sys.exit(OS_SUCCESS)
        
        session_id = find_user_session(username)
        
        if session_id:
            disconnect_session(session_id, username)
        
    except Exception as e:
        write_debug_file(script_name, f"UNEXPECTED ERROR: {str(e)}")
    finally:
        sys.exit(OS_SUCCESS)

if __name__ == "__main__":
    main(sys.argv)