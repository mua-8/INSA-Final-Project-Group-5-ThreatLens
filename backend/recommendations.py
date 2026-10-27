"""ThreatLens - Admin Security Recommendations & Auto-Defense Engine.

Provides automated mitigation actions and step-by-step administrator remediation
guidance for detected cyber attacks (RSD Detection Rules & Web Attacks).
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional


RECOMMENDATIONS_REGISTRY: Dict[str, Dict[str, Any]] = {
    "DR-01": {
        "rule_id": "DR-01",
        "attack_name": "SSH Brute Force (Multi-Password Guessing)",
        "threat_level": "Medium",
        "summary": "Attacker is attempting rapid repeated password guesses from a single source IP.",
        "auto_prevention_method": {
            "action": "Automated IP Quarantine & Connection Dropping",
            "description": "ThreatLens Auto-Defense immediately blacklists the source IP in the quarantine table and drops all subsequent incoming traffic.",
            "iptables_rule": "iptables -A INPUT -s {source_ip} -j DROP",
            "ufw_rule": "ufw deny from {source_ip}",
        },
        "immediate_actions": [
            "Verify the attacker IP {source_ip} is actively quarantined in ThreatLens Active Defense.",
            "Run firewall drop rule: `sudo iptables -A INPUT -s {source_ip} -j DROP` or `sudo ufw deny from {source_ip}`.",
            "Check for any accepted logins from this IP during the attack window.",
        ],
        "system_hardening": [
            {
                "title": "Disable SSH Password Authentication",
                "detail": "Enforce cryptographic public key authentication only. Edit `/etc/ssh/sshd_config` and set `PasswordAuthentication no`.",
                "command": "sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl reload sshd"
            },
            {
                "title": "Change Default SSH Port",
                "detail": "Move SSH listening port from default 22 to a non-standard port (e.g. 2222 or 52222) to eliminate automated Internet scanners.",
                "command": "echo 'Port 2222' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart sshd"
            },
            {
                "title": "Deploy Fail2ban Rate Limiting",
                "detail": "Install and enable fail2ban with a max retry count of 3 and 24-hour ban time.",
                "command": "sudo apt install fail2ban -y && sudo systemctl enable --now fail2ban"
            },
            {
                "title": "Set MaxAuthTries",
                "detail": "Configure sshd to disconnect sessions after 3 failed attempts: `MaxAuthTries 3`.",
                "command": "echo 'MaxAuthTries 3' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl reload sshd"
            }
        ]
    },
    "DR-02": {
        "rule_id": "DR-02",
        "attack_name": "Username Enumeration",
        "threat_level": "Medium",
        "summary": "Attacker is probing system accounts to identify valid usernames for future targeted attacks.",
        "auto_prevention_method": {
            "action": "Attacker IP Flagged & Rate-Limited",
            "description": "ThreatLens marks the source IP as suspicious and suppresses detailed username disclosure in authentication feedback.",
            "iptables_rule": "iptables -A INPUT -s {source_ip} -j DROP",
            "ufw_rule": "ufw deny from {source_ip}",
        },
        "immediate_actions": [
            "Quarantine source IP {source_ip} to halt automated reconnaissance.",
            "Audit all invalid usernames attempted to detect if internal corporate naming patterns were leaked.",
            "Ensure system accounts (`daemon`, `bin`, `nobody`, `sys`) have no active shell.",
        ],
        "system_hardening": [
            {
                "title": "Lock Inactive & System Shells",
                "detail": "Set login shell for non-interactive service accounts to `/usr/sbin/nologin` or `/bin/false`.",
                "command": "sudo usermod -s /usr/sbin/nologin <system_user>"
            },
            {
                "title": "Enable Verbose Auth Logging",
                "detail": "Configure SSH daemon to record public key fingerprints and auth details with `LogLevel VERBOSE`.",
                "command": "echo 'LogLevel VERBOSE' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl reload sshd"
            },
            {
                "title": "Enforce Generic Error Messages",
                "detail": "Prevent timing discrepancies or different error messages between valid and invalid usernames."
            }
        ]
    },
    "DR-03": {
        "rule_id": "DR-03",
        "attack_name": "Password Spraying Campaign",
        "threat_level": "High",
        "summary": "Attacker is testing common passwords across multiple accounts to evade single-user lockouts.",
        "auto_prevention_method": {
            "action": "Automated Distributed Attack Block",
            "description": "ThreatLens correlates cross-account failures from {source_ip} and triggers an immediate network quarantine.",
            "iptables_rule": "iptables -A INPUT -s {source_ip} -j DROP",
            "ufw_rule": "ufw deny from {source_ip}",
        },
        "immediate_actions": [
            "Block IP {source_ip} immediately across edge firewalls.",
            "Audit the sprayed accounts for any suspicious successful logins.",
            "Notify account owners to reset passwords immediately.",
        ],
        "system_hardening": [
            {
                "title": "Mandate Multi-Factor Authentication (MFA/2FA)",
                "detail": "Require hardware security keys (FIDO2/WebAuthn) or TOTP authenticators for all remote SSH and web access.",
                "command": "sudo apt install libpam-google-authenticator -y"
            },
            {
                "title": "Configure Global Failure Rate Limiting",
                "detail": "Configure PAM pam_faillock or pam_tally2 across the entire subnet, not just per-user.",
                "command": "sudo authselect enable-feature with-faillock"
            },
            {
                "title": "Enforce Strong Password Complexity",
                "detail": "Prohibit common dictionary passwords, company names, or sequential digits."
            }
        ]
    },
    "DR-04": {
        "rule_id": "DR-04",
        "attack_name": "Compromise (Success After Failures)",
        "threat_level": "Critical",
        "summary": "Attacker successfully authenticated after multiple failed password attempts. High probability of credential breach!",
        "auto_prevention_method": {
            "action": "Critical Breach Quarantine & Active Session Termination",
            "description": "ThreatLens flags the incident as CRITICAL, adds {source_ip} to firewall quarantine, and issues session termination alerts.",
            "iptables_rule": "iptables -A INPUT -s {source_ip} -j DROP",
            "ufw_rule": "ufw deny from {source_ip}",
        },
        "immediate_actions": [
            "CRITICAL: Terminate active SSH sessions immediately: `sudo pkill -u <username> -9`.",
            "Revoke compromised user credentials and SSH keys in `~/.ssh/authorized_keys`.",
            "Isolate the host or container network to contain lateral movement.",
            "Inspect running processes with `ps aux`, `lsof -i`, and `ss -tulpn`.",
        ],
        "system_hardening": [
            {
                "title": "Terminate Compromised User Sessions",
                "detail": "Kill any shell processes currently owned by the affected account.",
                "command": "sudo pkill -KILL -u <username>"
            },
            {
                "title": "Audit Persistence Artifacts",
                "detail": "Check `/tmp`, `/var/tmp`, `crontab -l`, systemd timers, and `~/.ssh/authorized_keys` for backdoor keys.",
                "command": "sudo ls -la /tmp /var/tmp /etc/cron* ~/.ssh"
            },
            {
                "title": "Rotate Root and System Secrets",
                "detail": "Immediately change database credentials, API tokens, and private keys stored on this host."
            }
        ]
    },
    "DR-05": {
        "rule_id": "DR-05",
        "attack_name": "Root / Privileged Account Access",
        "threat_level": "High",
        "summary": "Direct authentication attempt against the root superuser account.",
        "auto_prevention_method": {
            "action": "Immediate Privileged Protection Ban",
            "description": "ThreatLens bans any remote IP attempting direct root authentication.",
            "iptables_rule": "iptables -A INPUT -s {source_ip} -j DROP",
            "ufw_rule": "ufw deny from {source_ip}",
        },
        "immediate_actions": [
            "Block IP {source_ip} at the firewall.",
            "Verify whether the root login attempt was accepted or failed.",
            "If accepted, declare an immediate severity-1 security incident.",
        ],
        "system_hardening": [
            {
                "title": "Disable Direct Root SSH Login",
                "detail": "Set `PermitRootLogin no` in `/etc/ssh/sshd_config`. Administrators must log in as unprivileged users and use `sudo`.",
                "command": "sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload sshd"
            },
            {
                "title": "Audit Sudo Privileges & Commands",
                "detail": "Enforce strict sudoers configuration with command whitelisting and sudo password prompts.",
                "command": "sudo cat /etc/sudoers /etc/sudoers.d/*"
            },
            {
                "title": "Restrict Root Access to Console / Bastion",
                "detail": "Limit root access strictly to physical console or verified jump-host bastion."
            }
        ]
    },
    "DR-06": {
        "rule_id": "DR-06",
        "attack_name": "SQL Injection (SQLi) Attack",
        "threat_level": "High",
        "summary": "Hostile SQL control sequences, quote escapes, or boolean tautologies detected in user input / request parameters.",
        "auto_prevention_method": {
            "action": "Automated WAF Quarantine & DB Parameterization Enforcement",
            "description": "ThreatLens actively neutralizes SQL injection by binding all values as literal strings via parameterized DB-API queries (preventing SQL command execution) and auto-quarantines {source_ip}.",
            "iptables_rule": "iptables -A INPUT -s {source_ip} -j DROP",
            "ufw_rule": "ufw deny from {source_ip}",
        },
        "immediate_actions": [
            "Quarantine source IP {source_ip} to prevent automated exploitation scripts (e.g. sqlmap).",
            "Verify all backend queries utilize parameterized placeholders (`?`), never string interpolation (`%s` or `f'{var}'`).",
            "Inspect application error logs to confirm no internal database schema details or stack traces were leaked.",
        ],
        "system_hardening": [
            {
                "title": "Strict Parameterized Queries (Prepared Statements)",
                "detail": "Ensure 100% of SQL statements pass user input through DB-API parameters `cursor.execute('SELECT * FROM t WHERE col = ?', (val,))`. ThreatLens repository layer enforces this strictly.",
                "command": "# Verified in ThreatLens backend/repository.py: All queries use parameterized (?) placeholders."
            },
            {
                "title": "Principle of Least Privilege for Database User",
                "detail": "Revoke administrative privileges (`DROP`, `ALTER`, `GRANT`, `FILE`, `SUPER`) from the web application database user.",
                "command": "REVOKE DROP, ALTER, GRANT OPTION ON *.* FROM 'app_user'@'%';"
            },
            {
                "title": "Deploy Web Application Firewall (WAF)",
                "detail": "Install and configure ModSecurity or Cloudflare WAF to inspect and drop SQLi signatures at the HTTP proxy level.",
                "command": "sudo apt install libapache2-mod-security2 -y"
            },
            {
                "title": "Disable Verbose Database Error Reporting",
                "detail": "Ensure database syntax errors return generic 400/500 JSON errors without SQL dialect information."
            }
        ]
    },
    "DR-07": {
        "rule_id": "DR-07",
        "attack_name": "Excessive Multi-Password Tries (Credential Stuffing)",
        "threat_level": "High",
        "summary": "High-velocity authentication failure bursts indicating an automated botnet or password cracker.",
        "auto_prevention_method": {
            "action": "Automated High-Velocity Rate Limiting & Ban",
            "description": "ThreatLens Auto-Defense detects anomalous attempt frequencies and permanently blocks {source_ip}.",
            "iptables_rule": "iptables -A INPUT -s {source_ip} -j DROP",
            "ufw_rule": "ufw deny from {source_ip}",
        },
        "immediate_actions": [
            "Block IP {source_ip} across all external gateways.",
            "Verify that rate-limiting and captcha barriers are triggered on authentication portals.",
        ],
        "system_hardening": [
            {
                "title": "Enable Progressive Delay / Backoff",
                "detail": "Implement exponential delay after each successive failed login attempt from the same client.",
            },
            {
                "title": "Block Tor Exit Nodes & Malicious Proxies",
                "detail": "Ingest known malicious threat intelligence feeds and automatically block known VPN/Tor exit nodes.",
            }
        ]
    }
}


def get_recommendations_for_rule(rule_id: str, source_ip: str = "Unknown IP") -> Dict[str, Any]:
    """Retrieve structured mitigation guidance and prevention details for a specific alert rule."""
    base = RECOMMENDATIONS_REGISTRY.get(rule_id, RECOMMENDATIONS_REGISTRY["DR-01"])
    ip = source_ip or "Attacker IP"
    
    # Format templates with actual attacker IP
    auto_prev = dict(base["auto_prevention_method"])
    auto_prev["description"] = auto_prev["description"].replace("{source_ip}", ip)
    auto_prev["iptables_rule"] = auto_prev["iptables_rule"].replace("{source_ip}", ip)
    auto_prev["ufw_rule"] = auto_prev["ufw_rule"].replace("{source_ip}", ip)

    immediate = [act.replace("{source_ip}", ip) for act in base["immediate_actions"]]

    return {
        "rule_id": base["rule_id"],
        "attack_name": base["attack_name"],
        "threat_level": base["threat_level"],
        "summary": base["summary"],
        "source_ip": ip,
        "auto_prevention_method": auto_prev,
        "immediate_actions": immediate,
        "system_hardening": base["system_hardening"],
    }


def get_all_attack_remediations() -> List[Dict[str, Any]]:
    """Return catalog of all attack remediation blueprints for the SOC Defense Center."""
    return [get_recommendations_for_rule(rid, "192.168.1.100") for rid in sorted(RECOMMENDATIONS_REGISTRY.keys())]
