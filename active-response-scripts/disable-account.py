#!/usr/bin/python3
# Script Active Response Wazuh - Désactivation de compte AD (Version améliorée)
# À déployer sur le Domain Controller uniquement

import os
import sys
import json
import datetime
import subprocess
import re
import socket
from pathlib import PureWindowsPath, PurePosixPath

# Configuration des logs
if os.name == 'nt':
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
    DEBUG_LOG = "C:\\wazuh_ad_disable.log"
    WHITELIST_FILE = "C:\\wazuh_ad_whitelist.txt"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"
    DEBUG_LOG = "/tmp/wazuh_ad_disable.log"
    WHITELIST_FILE = "/tmp/wazuh_ad_whitelist.txt"

# Constantes Wazuh
ADD_COMMAND = 0
DELETE_COMMAND = 1
OS_SUCCESS = 0
OS_INVALID = -1

class Message:
    def __init__(self):
        self.alert = ""
        self.command = 0

def write_debug_file(ar_name, msg):
    """Logging compatible Wazuh"""
    try:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(ar_name[ar_name.find("active-response"):])))
        log_line = f"{datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')} {ar_name_posix}: {msg}"
        
        with open(LOG_FILE, mode="a", encoding="utf-8") as log_file:
            log_file.write(log_line + "\n")
            
        with open(DEBUG_LOG, mode="a", encoding="utf-8") as debug_file:
            debug_file.write(f"[{datetime.datetime.now()}] {msg}\n")
            
    except Exception as e:
        print(f"LOG ERROR: {e} - {msg}", file=sys.stderr)

def setup_and_check_message(argv):
    """Parse le message Wazuh - CORRECTION : utiliser readline()"""
    try:
        # CORRECTION : Lire une seule ligne pour éviter le blocage
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
        write_debug_file(argv[0], f"Raw input: {input_str[:200] if 'input_str' in locals() else 'N/A'}")
        return None
    except Exception as e:
        write_debug_file(argv[0], f"Erreur lecture: {e}")
        return None

def extract_ad_user_info(alert_data):
    """Extrait les informations AD de l'alerte"""
    try:
        alert = alert_data
        
        # Format 1: parameters.alert
        if 'parameters' in alert_data and 'alert' in alert_data['parameters']:
            alert = alert_data['parameters']['alert']
        
        # Format 2: Direct alert
        elif 'alert' in alert_data:
            alert = alert_data.get('alert', alert_data)
        
        # Chercher le username
        def search_user(d, depth=0):
            if depth > 3 or not isinstance(d, dict):
                return None
            
            user_fields = [
                'subjectUserName', 'targetUserName', 'sourceUser',
                'srcuser', 'dstuser', 'accountName', 'user',
                'SubjectUserName', 'TargetUserName'
            ]
            
            for field in user_fields:
                val = d.get(field)
                if val and str(val).strip() not in ['-', 'N/A', 'NULL', '', 'SYSTEM']:
                    return str(val).strip()
            
            for key, value in d.items():
                if isinstance(value, dict):
                    result = search_user(value, depth + 1)
                    if result:
                        return result
            
            return None
        
        username = search_user(alert)
        
        if not username:
            write_debug_file("extract_ad", "Aucun username trouvé")
            return None, None
        
        # Extraire domaine et username
        if '\\' in username:
            domain, user = username.split('\\', 1)
        else:
            # Déduire le domaine depuis l'agent
            agent_name = alert.get('agent', {}).get('name', '')
            if '.' in agent_name:
                domain = agent_name.split('.', 1)[1].upper()
            else:
                # Utiliser le domaine local
                try:
                    domain = os.environ.get('USERDOMAIN', 'DOMAIN').upper()
                except:
                    domain = "DOMAIN"
            user = username
        
        return domain.upper(), user
        
    except Exception as e:
        write_debug_file("extract_ad", f"Erreur extraction: {e}")
        return None, None

def is_protected_account(domain, username):
    """Vérifie si c'est un compte protégé"""
    try:
        full_account = f"{domain}\\{username}".upper()
        username_upper = username.upper()
        
        # Liste des comptes système critiques
        protected_accounts = [
            'ADMINISTRATOR', 'ADMIN', 'KRBTGT', 'SYSTEM',
            'DOMAIN ADMINS', 'ENTERPRISE ADMINS', 'SCHEMA ADMINS',
            'ORGANIZATION MANAGEMENT', 'EXCHANGE',
            'LOCAL SYSTEM', 'NETWORK SERVICE', 'LOCAL SERVICE'
        ]
        
        # Vérifier whitelist personnalisée
        if os.path.exists(WHITELIST_FILE):
            try:
                with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
                    whitelist = [line.strip().upper() for line in f if line.strip()]
                    if full_account in whitelist or username_upper in whitelist:
                        write_debug_file("protection", f"Compte en whitelist: {full_account}")
                        return True  # Retourne True pour "protégé par whitelist"
            except Exception as e:
                write_debug_file("protection", f"Erreur lecture whitelist: {e}")
        
        # Vérifier les comptes protégés
        for protected in protected_accounts:
            if protected in full_account or protected in username_upper:
                return True
        
        return False
        
    except Exception as e:
        write_debug_file("protection", f"Erreur vérification protection: {e}")
        return True  # En cas d'erreur, on protège par défaut

def disable_ad_account_safe(domain, username, source_agent):
    """Désactive un compte AD de manière sécurisée"""
    try:
        # Vérifier d'abord si le module AD est disponible
        check_module_cmd = "Get-Module -ListAvailable -Name ActiveDirectory"
        
        module_result = subprocess.run(
            ["powershell", "-Command", check_module_cmd],
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if "ActiveDirectory" in module_result.stdout:
            write_debug_file("disable_ad", "Module ActiveDirectory disponible")
            return disable_with_powershell_ad(domain, username, source_agent)
        else:
            write_debug_file("disable_ad", "Module ActiveDirectory non disponible, fallback net user")
            return disable_with_net_user(domain, username)
            
    except subprocess.TimeoutExpired:
        write_debug_file("disable_ad", "Timeout vérification module")
        return disable_with_net_user(domain, username)
    except Exception as e:
        write_debug_file("disable_ad", f"Erreur vérification: {e}")
        return False

def disable_with_powershell_ad(domain, username, source_agent):
    """Désactivation avec PowerShell AD module"""
    try:
        # 1. Vérifier l'existence du compte
        check_cmd = f"""
        try {{
            $user = Get-ADUser -Filter {{SamAccountName -eq '{username}'}} -Server '{domain}' -ErrorAction Stop
            if ($user) {{
                Write-Output "FOUND:$($user.SamAccountName):$($user.Enabled)"
            }} else {{
                Write-Output "NOTFOUND"
            }}
        }} catch {{
            Write-Output "ERROR:$($_.Exception.Message)"
        }}
        """
        
        check_result = subprocess.run(
            ["powershell", "-Command", check_cmd],
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if check_result.returncode != 0:
            write_debug_file("disable_ad", f"Erreur vérification compte: {check_result.stderr}")
            return False
        
        output = check_result.stdout.strip()
        
        if output.startswith("NOTFOUND"):
            write_debug_file("disable_ad", f"Compte {domain}\\{username} non trouvé")
            return False
        elif output.startswith("ERROR:"):
            write_debug_file("disable_ad", f"Erreur AD: {output}")
            return False
        elif output.startswith("FOUND:"):
            # Exemple: FOUND:jdoe:True
            parts = output.split(":")
            is_enabled = parts[2] == "True" if len(parts) > 2 else True
            
            if not is_enabled:
                write_debug_file("disable_ad", f"Compte {domain}\\{username} déjà désactivé")
                return True
        
        # 2. Désactiver le compte
        disable_cmd = f"""
        try {{
            Disable-ADAccount -Identity '{username}' -Server '{domain}' -Confirm:$false -ErrorAction Stop
            Write-Output "SUCCESS"
        }} catch {{
            Write-Output "ERROR:$($_.Exception.Message)"
        }}
        """
        
        disable_result = subprocess.run(
            ["powershell", "-Command", disable_cmd],
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if disable_result.returncode == 0 and "SUCCESS" in disable_result.stdout:
            write_debug_file("disable_ad", f"SUCCÈS: Compte {domain}\\{username} désactivé")
            
            # Journaliser l'action
            log_security_event(domain, username, source_agent, "Désactivation compte AD")
            
            return True
        else:
            error_msg = disable_result.stderr or disable_result.stdout
            write_debug_file("disable_ad", f"ÉCHEC désactivation: {error_msg}")
            return False
            
    except subprocess.TimeoutExpired:
        write_debug_file("disable_ad", "Timeout PowerShell AD")
        return False
    except Exception as e:
        write_debug_file("disable_ad", f"Exception PowerShell AD: {e}")
        return False

def disable_with_net_user(domain, username):
    """Fallback avec net user (local seulement)"""
    try:
        # net user fonctionne seulement sur le domaine local du DC
        current_domain = os.environ.get('USERDOMAIN', '').upper()
        
        if domain != current_domain:
            write_debug_file("disable_net", f"net user ne supporte pas le domaine {domain}, seulement {current_domain}")
            return False
        
        # Vérifier si le compte existe localement
        check_cmd = f"net user {username}"
        check_result = subprocess.run(
            check_cmd,
            shell=True,
            capture_output=True,
            text=True,
            encoding='cp850',
            timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if "The command completed successfully" not in check_result.stdout:
            write_debug_file("disable_net", f"Compte {username} non trouvé localement")
            return False
        
        # Désactiver le compte
        disable_cmd = f"net user {username} /ACTIVE:NO"
        disable_result = subprocess.run(
            disable_cmd,
            shell=True,
            capture_output=True,
            text=True,
            encoding='cp850',
            timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if disable_result.returncode == 0:
            write_debug_file("disable_net", f"SUCCÈS (net): {username} désactivé localement")
            return True
        else:
            write_debug_file("disable_net", f"ÉCHEC (net): {disable_result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        write_debug_file("disable_net", "Timeout net user")
        return False
    except Exception as e:
        write_debug_file("disable_net", f"Exception net: {e}")
        return False

def disconnect_targeted_sessions(domain, username, source_agent):
    """Déconnecte les sessions SUR LA MACHINE SOURCE uniquement (optimisé)"""
    try:
        # Obtenir le nom de la machine source depuis l'alerte
        # Cette fonction est optionnelle et peut être commentée si non nécessaire
        
        write_debug_file("disconnect", f"Optionnel: déconnexion sessions pour {username}")
        
        # Si on a l'information de la machine source, on peut cibler spécifiquement
        if source_agent and source_agent != socket.gethostname():
            # C'est une machine différente du DC
            disconnect_cmd = f"""
            $targetComputer = "{source_agent}"
            try {{
                $sessions = qwinsta /SERVER:$targetComputer 2>$null
                if ($LASTEXITCODE -eq 0) {{
                    $matchingSessions = $sessions | Select-String -Pattern "{username}" -CaseSensitive:$false
                    foreach ($session in $matchingSessions) {{
                        $parts = $session -split '\s+'
                        if ($parts.Count -ge 3 -and $parts[2] -match '^\d+$') {{
                            $sessionId = $parts[2]
                            logoff $sessionId /SERVER:$targetComputer 2>$null
                            Write-Host "Déconnecté session $sessionId sur $targetComputer"
                        }}
                    }}
                }}
            }} catch {{
                Write-Host "Erreur ciblage $targetComputer: $_"
            }}
            """
            
            result = subprocess.run(
                ["powershell", "-Command", disconnect_cmd],
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                write_debug_file("disconnect", f"Sessions ciblées sur {source_agent}")
        
        return True
        
    except Exception as e:
        write_debug_file("disconnect", f"Exception déconnexion ciblée: {e}")
        return False

def log_security_event(domain, username, source_agent, action):
    """Journalise l'action dans le journal de sécurité Windows"""
    try:
        event_message = f"""
        Action de sécurité automatisée - Wazuh Active Response
        
        Compte AD: {domain}\\{username}
        Action: {action}
        Source: {source_agent}
        Heure: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        Raison: Détection de vol d'identifiants (Credential Dumping)
        """
        
        # Utiliser eventcreate pour compatibilité
        event_cmd = f"""
        eventcreate /L SECURITY /T WARNING /SO "Wazuh AR" /ID 4725 /D "{event_message}"
        """
        
        result = subprocess.run(
            event_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if result.returncode == 0:
            write_debug_file("log_event", f"Événement 4725 créé pour {domain}\\{username}")
        else:
            write_debug_file("log_event", f"Échec création événement: {result.stderr}")
            
    except Exception as e:
        write_debug_file("log_event", f"Exception journalisation: {e}")

def main(argv):
    script_name = argv[0] if argv else "ad-account-disable"
    write_debug_file(script_name, "=" * 60)
    write_debug_file(script_name, "AD ACCOUNT DISABLE - ACTIVE RESPONSE STARTED")
    
    try:
        # 1. Parse message Wazuh
        msg = setup_and_check_message(argv)
        if not msg:
            write_debug_file(script_name, "Message invalide - sortie propre")
            sys.exit(OS_SUCCESS)
        
        # 2. Traiter seulement ADD commands
        if msg.command != ADD_COMMAND:
            write_debug_file(script_name, "Commande DELETE ignorée (nettoyage)")
            sys.exit(OS_SUCCESS)
        
        write_debug_file(script_name, "Traitement alerte credential theft")
        
        # 3. Extraire informations AD
        domain, username = extract_ad_user_info(msg.alert)
        
        if not domain or not username:
            write_debug_file(script_name, "Impossible d'extraire domaine/username")
            sys.exit(OS_SUCCESS)
        
        write_debug_file(script_name, f"Compte cible identifié: {domain}\\{username}")
        
        # 4. Vérifier comptes protégés
        if is_protected_account(domain, username):
            write_debug_file(script_name, f"SECURITE: Compte protégé {domain}\\{username} - Action bloquée")
            log_security_event(domain, username, "Wazuh AR", "Tentative de désactivation bloquée (compte protégé)")
            sys.exit(OS_SUCCESS)
        
        # 5. Obtenir l'agent source
        alert = msg.alert.get('parameters', {}).get('alert', msg.alert.get('alert', msg.alert))
        source_agent = alert.get('agent', {}).get('name', 'Inconnu')
        
        # 6. Désactiver le compte
        write_debug_file(script_name, f"Tentative de désactivation de {domain}\\{username}")
        
        if disable_ad_account_safe(domain, username, source_agent):
            write_debug_file(script_name, f"SUCCES: Compte {domain}\\{username} désactivé")
            
            # 7. Optionnel: Déconnecter les sessions sur la machine source
            disconnect_targeted_sessions(domain, username, source_agent)
            
        else:
            write_debug_file(script_name, f"ECHEC: Impossible de désactiver {domain}\\{username}")
        
        write_debug_file(script_name, "AD ACCOUNT DISABLE - ACTIVE RESPONSE COMPLETED")
        
    except Exception as e:
        write_debug_file(script_name, f"ERREUR INATTENDUE: {type(e).__name__}: {str(e)}")
        import traceback
        write_debug_file(script_name, f"Traceback: {traceback.format_exc()}")
        
    finally:
        write_debug_file(script_name, "=" * 60)
        sys.exit(OS_SUCCESS)

if __name__ == "__main__":
    main(sys.argv)