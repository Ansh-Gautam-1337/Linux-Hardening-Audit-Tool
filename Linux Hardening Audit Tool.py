#!/usr/bin/env python3
import os
import subprocess
import stat
import platform
import re
import datetime
import argparse

# --- Constants ---

# For colorized output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# CIS-inspired scoring
class Score:
    total_max_score = 0
    total_actual_score = 0

# Report storage
class Report:
    results = []

    @classmethod
    def add(cls, check_id, description, status, recommendation, cis_ref, score, max_score):
        """Adds a check result to the report."""
        cls.results.append({
            "id": check_id,
            "description": description,
            "status": status,
            "recommendation": recommendation,
            "cis_ref": cis_ref,
            "score": score,
            "max_score": max_score,
        })
        Score.total_max_score += max_score
        Score.total_actual_score += score

# --- Helper Functions ---

def print_header(title):
    """Prints a formatted header."""
    print("\n" + "="*80)
    print(f"{Colors.HEADER}{Colors.BOLD}{title.center(80)}{Colors.ENDC}")
    print("="*80)

def print_section_header(title):
    """Prints a section header."""
    print(f"\n--- {Colors.BLUE}{Colors.BOLD}{title}{Colors.ENDC} ---\n")

def get_status_color(status):
    """Returns a color based on the status string."""
    if status == "PASS":
        return Colors.GREEN
    elif status == "FAIL":
        return Colors.RED
    else:  # WARN
        return Colors.YELLOW

def run_command(command, shell=False):
    """Executes a shell command and returns its output, handling errors."""
    try:
        if shell:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, check=False)
        else:
            result = subprocess.run(command.split(), capture_output=True, text=True, check=False)

        if result.returncode != 0 and result.stderr:
            # Don't print an error for commands that are expected to fail sometimes (e.g., checking for a non-existent package)
            pass
        return result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        return None, f"Command not found: {command.split()[0]}"
    except Exception as e:
        return None, str(e)

def check_root_privileges():
    """Checks if the script is run with root privileges."""
    if os.geteuid() != 0:
        print(f"{Colors.RED}Error: This script must be run as root to access system configuration files.{Colors.ENDC}")
        print("Please run with 'sudo'.")
        exit(1)

def get_os_info():
    """Gathers basic OS information."""
    try:
        return platform.freedesktop_os_release()
    except Exception:
        return {"ID": "unknown", "PRETTY_NAME": "Unknown Linux"}

# --- Audit Check Functions ---

def check_firewall_status():
    """
    1. Filesystem and Partitions
    Audits the firewall configuration (UFW or firewalld).
    """
    print_section_header("1. Firewall Configuration")
    max_score_per_check = 5
    
    # Check for UFW
    ufw_output, _ = run_command("ufw status")
    if ufw_output and "Status: active" in ufw_output:
        Report.add("FW-001", "UFW Firewall Status", "PASS", "UFW is active and configured.", "CIS 3.5.1.1", max_score_per_check, max_score_per_check)
        return

    # Check for firewalld
    firewalld_output, _ = run_command("systemctl is-active firewalld")
    if firewalld_output == "active":
        Report.add("FW-001", "firewalld Status", "PASS", "firewalld is active and configured.", "CIS 3.5.2.1", max_score_per_check, max_score_per_check)
        return

    # Check for iptables (basic check if rules exist)
    iptables_output, _ = run_command("iptables -L -n")
    if iptables_output and "Chain INPUT (policy ACCEPT)" not in iptables_output:
        Report.add("FW-001", "iptables Status", "PASS", "iptables appears to have rules configured.", "CIS 3.5.3.1", max_score_per_check, max_score_per_check)
        return

    Report.add("FW-001", "Firewall Status", "FAIL", "No active and configured firewall (UFW, firewalld, or iptables) was found.", "CIS 3.5", 0, max_score_per_check)

def check_unused_services():
    """
    2. Unused Services
    Identifies common unnecessary services that are enabled.
    """
    print_section_header("2. Unused Services")
    max_score = 10
    current_score = max_score
    
    # List of services that are often considered unnecessary on hardened servers
    unnecessary_services = [
        "telnet.socket", "rsh.socket", "rlogin.socket", "ypbind.service",
        "tftp.socket", "nfs-server.service", "rpcbind.socket", "avahi-daemon.service",
        "cups.service"
    ]
    
    found_unnecessary = []
    
    enabled_services, _ = run_command("systemctl list-unit-files --state=enabled")
    if enabled_services is None:
        Report.add("SVC-001", "Check Unnecessary Services", "WARN", "Could not retrieve list of enabled services.", "CIS 2.2", 5, max_score)
        return
        
    for service in unnecessary_services:
        if service in enabled_services:
            found_unnecessary.append(service)
            # Deduct points for each found service
            current_score = max(0, current_score - 2)

    if not found_unnecessary:
        Report.add("SVC-001", "Check Unnecessary Services", "PASS", "No common unnecessary services found enabled.", "CIS 2.2", max_score, max_score)
    else:
        recommendation = f"Disable the following unnecessary services: {', '.join(found_unnecessary)}."
        Report.add("SVC-001", "Check Unnecessary Services", "FAIL", recommendation, "CIS 2.2", current_score, max_score)

def check_ssh_configuration():
    """
    3. SSH Configuration
    Audits the SSH daemon configuration for secure settings.
    """
    print_section_header("3. SSH Configuration")
    ssh_config_file = "/etc/ssh/sshd_config"
    max_score_per_check = 2
    
    if not os.path.exists(ssh_config_file):
        Report.add("SSH-001", "SSH Configuration File", "FAIL", f"{ssh_config_file} not found.", "CIS 5.2", 0, 10)
        return

    with open(ssh_config_file, 'r') as f:
        config_lines = f.readlines()

    config = {}
    for line in config_lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) >= 2:
            config[parts[0]] = parts[1]

    # SSH-002: Protocol 2
    if config.get("Protocol") == "2":
        Report.add("SSH-002", "SSH Protocol Version", "PASS", "SSH Protocol is set to 2.", "CIS 5.2.1", max_score_per_check, max_score_per_check)
    else:
        Report.add("SSH-002", "SSH Protocol Version", "FAIL", "Set 'Protocol 2' in sshd_config.", "CIS 5.2.1", 0, max_score_per_check)

    # SSH-003: PermitRootLogin
    if config.get("PermitRootLogin") == "no":
        Report.add("SSH-003", "PermitRootLogin", "PASS", "Root login is disabled.", "CIS 5.2.3", max_score_per_check, max_score_per_check)
    else:
        Report.add("SSH-003", "PermitRootLogin", "FAIL", "Set 'PermitRootLogin no' in sshd_config.", "CIS 5.2.3", 0, max_score_per_check)

    # SSH-004: PasswordAuthentication
    if config.get("PasswordAuthentication") == "no":
        Report.add("SSH-004", "PasswordAuthentication", "PASS", "Password authentication is disabled (key-based auth preferred).", "CIS 5.2.11", max_score_per_check, max_score_per_check)
    else:
        Report.add("SSH-004", "PasswordAuthentication", "WARN", "Consider disabling password authentication. Set 'PasswordAuthentication no'.", "CIS 5.2.11", 1, max_score_per_check)

    # SSH-005: X11Forwarding
    if config.get("X11Forwarding") == "no":
        Report.add("SSH-005", "X11Forwarding", "PASS", "X11Forwarding is disabled.", "CIS 5.2.9", max_score_per_check, max_score_per_check)
    else:
        Report.add("SSH-005", "X11Forwarding", "FAIL", "Set 'X11Forwarding no' in sshd_config.", "CIS 5.2.9", 0, max_score_per_check)
        
    # SSH-006: MaxAuthTries
    max_auth_tries = config.get("MaxAuthTries")
    if max_auth_tries and int(max_auth_tries) <= 4:
        Report.add("SSH-006", "MaxAuthTries", "PASS", f"MaxAuthTries is set to a secure value ({max_auth_tries}).", "CIS 5.2.4", max_score_per_check, max_score_per_check)
    else:
        Report.add("SSH-006", "MaxAuthTries", "FAIL", "Set 'MaxAuthTries' to a value of 4 or less.", "CIS 5.2.4", 0, max_score_per_check)

    # SSH-007: PermitEmptyPasswords
    if config.get("PermitEmptyPasswords") == "no":
        Report.add("SSH-007", "PermitEmptyPasswords", "PASS", "Permitting empty passwords is disabled.", "CIS 5.2.7", max_score_per_check, max_score_per_check)
    else:
        Report.add("SSH-007", "PermitEmptyPasswords", "FAIL", "Set 'PermitEmptyPasswords no' in sshd_config.", "CIS 5.2.7", 0, max_score_per_check)

def check_file_permissions():
    """
    4. Critical File Permissions
    Verifies permissions and ownership of key system files.
    """
    print_section_header("4. Critical File Permissions")
    
    files_to_check = {
        "/etc/passwd": {"perm": "644", "owner": "root", "group": "root"},
        "/etc/shadow": {"perm": "640", "owner": "root", "group": "shadow"},
        "/etc/group": {"perm": "644", "owner": "root", "group": "root"},
        "/etc/sudoers": {"perm": "440", "owner": "root", "group": "root"},
        "/etc/gshadow": {"perm": "640", "owner": "root", "group": "shadow"},
        "/etc/ssh/sshd_config": {"perm": "600", "owner": "root", "group": "root"},
    }
    
    max_score_per_check = 2

    for fpath, expected in files_to_check.items():
        check_id = f"PERM-{fpath.replace('/', '-')}"
        if not os.path.exists(fpath):
            Report.add(check_id, f"File Existence: {fpath}", "FAIL", f"File {fpath} not found.", "CIS 6.1", 0, max_score_per_check)
            continue

        try:
            f_stat = os.stat(fpath)
            mode = stat.S_IMODE(f_stat.st_mode)
            perm_str = oct(mode)[-3:]
            
            owner_uid = f_stat.st_uid
            group_gid = f_stat.st_gid
            
            # This is a simplification; a robust check would use the pwd/grp modules
            owner_name = "root" if owner_uid == 0 else "non-root"
            group_name = "root" if group_gid == 0 else "shadow" if group_gid == 42 else "non-root" # Common shadow GID
            
            perm_ok = perm_str == expected["perm"]
            owner_ok = owner_name == expected["owner"]
            group_ok = group_name in (expected["group"], "root") # Be flexible with root vs shadow group
            
            if perm_ok and owner_ok and group_ok:
                Report.add(check_id, f"Permissions for {fpath}", "PASS", f"Permissions are correctly set to {expected['perm']}.", "CIS 6.1", max_score_per_check, max_score_per_check)
            else:
                issues = []
                if not perm_ok: issues.append(f"permission is {perm_str} (should be {expected['perm']})")
                if not owner_ok: issues.append(f"owner is incorrect")
                if not group_ok: issues.append(f"group is incorrect")
                recommendation = f"Check {fpath}: {', '.join(issues)}."
                Report.add(check_id, f"Permissions for {fpath}", "FAIL", recommendation, "CIS 6.1", 0, max_score_per_check)
        except Exception as e:
            Report.add(check_id, f"Permissions for {fpath}", "WARN", f"Could not check file {fpath}: {e}", "CIS 6.1", 0, max_score_per_check)

def check_rootkit_indicators():
    """
    5. Rootkit and Malware Indicators
    Performs basic checks for rootkits.
    """
    print_section_header("5. Rootkit and Malware Indicators")
    max_score = 5

    # Check for chkrootkit
    chkrootkit_path, _ = run_command("which chkrootkit")
    if chkrootkit_path:
        Report.add("RKIT-001", "chkrootkit Installation", "PASS", "chkrootkit is installed. Run it manually for a full scan.", "N/A", max_score, max_score)
    else:
        Report.add("RKIT-001", "chkrootkit Installation", "WARN", "chkrootkit is not installed. Install it for system integrity checks.", "N/A", 2, max_score)

    # Check for rkhunter
    rkhunter_path, _ = run_command("which rkhunter")
    if rkhunter_path:
        Report.add("RKIT-002", "rkhunter Installation", "PASS", "rkhunter is installed. Run it manually for a full scan.", "N/A", max_score, max_score)
    else:
        Report.add("RKIT-002", "rkhunter Installation", "WARN", "rkhunter is not installed. Install it for system integrity checks.", "N/A", 2, max_score)

    # Check for promiscuous mode interfaces
    promisc_output, _ = run_command("ip link")
    if promisc_output and "PROMISC" in promisc_output:
        Report.add("RKIT-003", "Promiscuous Mode", "FAIL", "One or more network interfaces are in promiscuous mode.", "N/A", 0, max_score)
    else:
        Report.add("RKIT-003", "Promiscuous Mode", "PASS", "No network interfaces found in promiscuous mode.", "N/A", max_score, max_score)
        
def check_password_policies():
    """
    6. Password Policies
    Checks for strong password policies in /etc/login.defs and PAM.
    """
    print_section_header("6. Password Policies")
    login_defs_file = "/etc/login.defs"
    max_score_per_check = 2
    
    if not os.path.exists(login_defs_file):
        Report.add("PASS-001", "Password Policies File", "FAIL", f"{login_defs_file} not found.", "CIS 5.3", 0, 8)
        return

    config = {}
    with open(login_defs_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) >= 2:
                config[parts[0]] = parts[1]

    # Check PASS_MAX_DAYS
    max_days = int(config.get("PASS_MAX_DAYS", 99999))
    if max_days <= 90:
        Report.add("PASS-002", "Password Max Age", "PASS", f"Password max age is set to {max_days} days (<= 90).", "CIS 5.3.1", max_score_per_check, max_score_per_check)
    else:
        Report.add("PASS-002", "Password Max Age", "FAIL", "Set PASS_MAX_DAYS to 90 or less in /etc/login.defs.", "CIS 5.3.1", 0, max_score_per_check)

    # Check PASS_MIN_DAYS
    min_days = int(config.get("PASS_MIN_DAYS", 0))
    if min_days >= 7:
        Report.add("PASS-003", "Password Min Age", "PASS", f"Password min age is set to {min_days} days (>= 7).", "CIS 5.3.1", max_score_per_check, max_score_per_check)
    else:
        Report.add("PASS-003", "Password Min Age", "FAIL", "Set PASS_MIN_DAYS to 7 or more in /etc/login.defs.", "CIS 5.3.1", 0, max_score_per_check)

    # Check for pam_pwquality or pam_cracklib for complexity
    pam_file = "/etc/pam.d/common-password"
    if not os.path.exists(pam_file):
        pam_file = "/etc/pam.d/system-auth" # Fallback for RHEL-based systems
        
    if os.path.exists(pam_file):
        with open(pam_file, 'r') as f:
            content = f.read()
        if "pam_pwquality.so" in content or "pam_cracklib.so" in content:
            Report.add("PASS-004", "Password Complexity", "PASS", "Password complexity is likely enforced via PAM.", "CIS 5.3.2", max_score_per_check, max_score_per_check)
        else:
            Report.add("PASS-004", "Password Complexity", "FAIL", "Enforce password complexity using pam_pwquality.so or pam_cracklib.so.", "CIS 5.3.2", 0, max_score_per_check)
    else:
        Report.add("PASS-004", "Password Complexity", "WARN", "Could not find a common PAM file to check for password complexity.", "CIS 5.3.2", 1, max_score_per_check)

def check_auditd_status():
    """
    7. System Auditing
    Checks if auditd is installed and running.
    """
    print_section_header("7. System Auditing (auditd)")
    max_score = 5
    
    auditd_active, _ = run_command("systemctl is-active auditd")
    auditd_enabled, _ = run_command("systemctl is-enabled auditd")
    
    if auditd_active == "active" and auditd_enabled == "enabled":
        Report.add("AUDIT-001", "auditd Service Status", "PASS", "auditd service is active and enabled.", "CIS 4.1.1", max_score, max_score)
    elif auditd_active == "active":
        Report.add("AUDIT-001", "auditd Service Status", "WARN", "auditd service is active but not enabled to start on boot.", "CIS 4.1.1", 3, max_score)
    else:
        Report.add("AUDIT-001", "auditd Service Status", "FAIL", "auditd service is not running. Install and enable it for system auditing.", "CIS 4.1.1", 0, max_score)


# --- Report Generation ---

def generate_report():
    """Formats and prints the final audit report."""
    print_header("Linux Security Audit Report")

    # --- System Information ---
    os_info = get_os_info()
    print(f"{Colors.BOLD}Date of Audit:{Colors.ENDC}       {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Colors.BOLD}Operating System:{Colors.ENDC}    {os_info.get('PRETTY_NAME', 'Unknown')}")
    print(f"{Colors.BOLD}Hostname:{Colors.ENDC}            {platform.node()}")

    # --- Score Summary ---
    print_header("Audit Score Summary")
    if Score.total_max_score > 0:
        percentage = (Score.total_actual_score / Score.total_max_score) * 100
    else:
        percentage = 0

    score_color = Colors.GREEN if percentage >= 80 else Colors.YELLOW if percentage >= 50 else Colors.RED
    
    print(f"Total Score: {score_color}{Colors.BOLD}{Score.total_actual_score} / {Score.total_max_score}{Colors.ENDC}")
    print(f"Compliance Percentage: {score_color}{Colors.BOLD}{percentage:.2f}%{Colors.ENDC}")

    # --- Detailed Findings ---
    print_header("Detailed Findings")
    
    # Sort results by status: FAIL, WARN, PASS
    sorted_results = sorted(Report.results, key=lambda x: (x['status'] != 'FAIL', x['status'] != 'WARN', x['status'] != 'PASS'))

    for result in sorted_results:
        status_color = get_status_color(result['status'])
        print(f"[{status_color}{result['status']:<4}{Colors.ENDC}] {Colors.BOLD}{result['id']}: {result['description']}{Colors.ENDC}")
        print(f"         {Colors.BLUE}CIS Ref:{Colors.ENDC} {result['cis_ref']}")
        print(f"         {Colors.BLUE}Details:{Colors.ENDC} {result['recommendation']}")
        print("-" * 40)

    # --- Recommendations Summary ---
    print_header("Prioritized Recommendations")
    recommendations = [res for res in Report.results if res['status'] in ['FAIL', 'WARN']]
    
    if not recommendations:
        print(f"{Colors.GREEN}Excellent! No high-priority recommendations found.{Colors.ENDC}")
    else:
        print(f"{Colors.YELLOW}The following actions are recommended to harden the system:{Colors.ENDC}\n")
        fail_recs = [rec for rec in recommendations if rec['status'] == 'FAIL']
        warn_recs = [rec for rec in recommendations if rec['status'] == 'WARN']
        
        if fail_recs:
            print(f"{Colors.RED}{Colors.BOLD}High Priority (FAIL):{Colors.ENDC}")
            for i, rec in enumerate(fail_recs, 1):
                print(f"  {i}. {rec['recommendation']} ({rec['id']})")
        
        if warn_recs:
            print(f"\n{Colors.YELLOW}{Colors.BOLD}Medium Priority (WARN):{Colors.ENDC}")
            for i, rec in enumerate(warn_recs, 1):
                print(f"  {i}. {rec['recommendation']} ({rec['id']})")

    print("\n" + "="*80)
    print("End of Report".center(80))
    print("="*80)

# --- Main Execution ---

def main():
    """Main function to orchestrate the audit."""
    parser = argparse.ArgumentParser(
        description="Linux Hardening Audit Tool.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
This tool checks various security aspects of a Linux system.
It must be run with root privileges to function correctly.
Example: sudo python3 linux_audit_tool.py
"""
    )
    # This script is simple, so no complex arguments needed for now.
    # Can be extended with --check <module> or --output <file> later.
    args = parser.parse_args()

    check_root_privileges()

    print_header("Starting Linux Security Audit")
    print("This may take a moment...")

    # Execute all audit checks
    check_firewall_status()
    check_unused_services()
    check_ssh_configuration()
    check_file_permissions()
    check_rootkit_indicators()
    check_password_policies()
    check_auditd_status()
    
    # Generate and print the final report
    generate_report()


if __name__ == "__main__":
    main()