import subprocess
import os
import time
from utils import logger

SNORT_CONF_PATH = "C:/Snort/etc/snort.conf"
SNORT_RULES_PATH = "C:/Snort/rules/local.rules"
SNORT_LOG_PATH = "log/snort"
SNORT_PID_FILE = "log/snort/snort.pid"

def check_snort_status():
    """Check if Snort is running"""
    try:
        if os.path.exists(SNORT_PID_FILE):
            with open(SNORT_PID_FILE, 'r') as f:
                pid = f.read().strip()
                if pid:
                    # Check if process is actually running
                    result = subprocess.run(['tasklist', '/FI', f'PID eq {pid}'], 
                                         capture_output=True, text=True)
                    if f"snort.exe" in result.stdout.lower():
                        logger.info(f"Snort is running with PID {pid}")
                        return "running"
        return "stopped"
    except Exception as e:
        logger.error(f"Error checking Snort status: {e}")
        return "stopped"

def start_snort(interface):
    """Start Snort on the specified interface"""
    try:
        if check_snort_status() == "running":
            logger.info("Snort is already running")
            return True
        
        # Ensure log directory exists
        os.makedirs(SNORT_LOG_PATH, exist_ok=True)
        
        # Construct Snort command
        snort_cmd = [
            "C:/Snort/bin/snort.exe",
            "-i", interface,
            "-c", SNORT_CONF_PATH,
            "-l", SNORT_LOG_PATH,
            "-A", "console",
            "-k", "none",
            "-q"
        ]
        
        logger.info(f"Starting Snort with command: {' '.join(snort_cmd)}")
        
        # Start Snort as a background process
        process = subprocess.Popen(snort_cmd, 
                                 stdout=subprocess.PIPE, 
                                 stderr=subprocess.PIPE,
                                 creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        
        # Wait a moment to check if it started successfully
        time.sleep(2)
        
        if check_snort_status() == "running":
            logger.info("Snort started successfully")
            return True
        else:
            logger.error("Failed to start Snort")
            stderr = process.stderr.read().decode()
            if stderr:
                logger.error(f"Snort error output: {stderr}")
            return False
            
    except Exception as e:
        logger.error(f"Error starting Snort: {e}")
        return False

def stop_snort():
    """Stop the Snort service"""
    try:
        if check_snort_status() == "stopped":
            logger.info("Snort is already stopped")
            return True
            
        if os.path.exists(SNORT_PID_FILE):
            with open(SNORT_PID_FILE, 'r') as f:
                pid = f.read().strip()
                if pid:
                    try:
                        subprocess.run(['taskkill', '/PID', pid, '/F'], 
                                     capture_output=True, 
                                     check=True)
                        logger.info(f"Terminated Snort process with PID {pid}")
                    except subprocess.CalledProcessError as e:
                        logger.error(f"Error terminating Snort process: {e}")
                    
                    # Clean up PID file
                    try:
                        os.remove(SNORT_PID_FILE)
                    except OSError as e:
                        logger.error(f"Error removing Snort PID file: {e}")
        
        # Verify Snort is stopped
        if check_snort_status() == "stopped":
            logger.info("Snort stopped successfully")
            return True
        else:
            logger.warning("Snort stop command sent, but process may still be running")
            return False
            
    except Exception as e:
        logger.error(f"Error stopping Snort: {e}")
        return False

def update_snort_rules(ip, block=True):
    """Update Snort rules to block or unblock an IP"""
    try:
        # Ensure rules file exists
        if not os.path.exists(SNORT_RULES_PATH):
            with open(SNORT_RULES_PATH, 'w') as f:
                f.write("# Snort local rules\n")
        
        # Read current rules
        with open(SNORT_RULES_PATH, 'r') as f:
            rules = f.readlines()
        
        # Remove existing rules for this IP
        rules = [rule for rule in rules if ip not in rule]
        
        if block:
            # Add block rules
            rule_in = f'drop ip {ip} any -> any any (msg:"Blocking IP {ip} inbound"; sid:100000{len(rules)+1};)\n'
            rule_out = f'drop ip any any -> {ip} any (msg:"Blocking IP {ip} outbound"; sid:100000{len(rules)+2};)\n'
            rules.append(rule_in)
            rules.append(rule_out)
            logger.info(f"Added Snort rules to block IP: {ip}")
        else:
            logger.info(f"Removed Snort rules for IP: {ip}")
        
        # Write updated rules
        with open(SNORT_RULES_PATH, 'w') as f:
            f.writelines(rules)
        
        return True
    except Exception as e:
        logger.error(f"Error updating Snort rules for IP {ip}: {e}")
        return False

def reload_snort_rules():
    """Reload Snort rules without restarting the service"""
    try:
        if check_snort_status() == "running":
            # Find Snort process
            if os.path.exists(SNORT_PID_FILE):
                with open(SNORT_PID_FILE, 'r') as f:
                    pid = f.read().strip()
                    if pid:
                        # Send SIGHUP equivalent to reload rules
                        subprocess.run(['taskkill', '/PID', pid, '/T'], 
                                     capture_output=True)
                        time.sleep(1)
                        logger.info("Sent reload signal to Snort")
                        return True
        logger.warning("Snort is not running, cannot reload rules")
        return False
    except Exception as e:
        logger.error(f"Error reloading Snort rules: {e}")
        return False