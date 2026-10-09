import logging
import os
import platform
import subprocess
import re
from datetime import datetime, timezone
from queue import Queue
from typing import List, Dict, Any, Optional, Tuple

log = logging.getLogger("chael-cis")

CIS_CHECKS_LINUX: Dict[str, Dict[str, Any]] = {
    "1.1.1": {
        "title": "Filesystem: Disable unused filesystems",
        "description": "Ensure mounting of cramfs, freevxfs, hfs, hfsplus, squashfs, udf, vfat filesystems is disabled",
        "commands": [
            ["lsmod | grep cramfs", "test ! -d /proc/fs/cramfs"],
        ],
        "severity": "MEDIUM",
        "category": "filesystem",
    },
    "1.1.2": {
        "title": "Filesystem: Separate partition for /tmp",
        "description": "Ensure /tmp is a separate partition",
        "commands": [
            ["mount | grep -E '\\s/tmp\\s'"],
        ],
        "severity": "MEDIUM",
        "category": "filesystem",
    },
    "1.1.3": {
        "title": "Filesystem: Nodev option on /tmp",
        "description": "Ensure nodev option set on /tmp partition",
        "commands": [
            ["mount | grep -E '\\s/tmp\\s' | grep nodev"],
        ],
        "severity": "MEDIUM",
        "category": "filesystem",
    },
    "1.1.4": {
        "title": "Filesystem: Nosuid option on /tmp",
        "description": "Ensure nosuid option set on /tmp partition",
        "commands": [
            ["mount | grep -E '\\s/tmp\\s' | grep nosuid"],
        ],
        "severity": "MEDIUM",
        "category": "filesystem",
    },
    "1.1.5": {
        "title": "Filesystem: Separate partition for /var",
        "description": "Ensure /var is a separate partition",
        "commands": [
            ["mount | grep -E '\\s/var\\s'"],
        ],
        "severity": "MEDIUM",
        "category": "filesystem",
    },
    "1.1.6": {
        "title": "Filesystem: Separate partition for /var/log",
        "description": "Ensure /var/log is a separate partition",
        "commands": [
            ["mount | grep -E '\\s/var/log\\s'"],
        ],
        "severity": "MEDIUM",
        "category": "filesystem",
    },
    "1.1.7": {
        "title": "Filesystem: Separate partition for /var/log/audit",
        "description": "Ensure /var/log/audit is a separate partition",
        "commands": [
            ["mount | grep -E '\\s/var/log/audit\\s'"],
        ],
        "severity": "MEDIUM",
        "category": "filesystem",
    },
    "1.1.8": {
        "title": "Filesystem: Separate partition for /home",
        "description": "Ensure /home is a separate partition",
        "commands": [
            ["mount | grep -E '\\s/home\\s'"],
        ],
        "severity": "LOW",
        "category": "filesystem",
    },
    "1.2.1": {
        "title": "Package Repos: Configure GPG keys",
        "description": "Ensure package manager repositories are configured",
        "commands": [
            ["apt-key list 2>/dev/null | head -5", "test -f /etc/apt/trusted.gpg"],
        ],
        "severity": "MEDIUM",
        "category": "packages",
    },
    "1.3.1": {
        "title": "SELinux: Ensure SELinux is installed",
        "description": "Ensure SELinux is installed",
        "commands": [
            ["which getenforce 2>/dev/null || which sestatus 2>/dev/null"],
        ],
        "severity": "HIGH",
        "category": "selinux",
    },
    "1.3.2": {
        "title": "SELinux: Ensure SELinux is enforcing",
        "description": "Ensure SELinux is in enforcing mode",
        "commands": [
            ["getenforce 2>/dev/null | grep -i enforcing", "sestatus 2>/dev/null | grep 'Current mode' | grep -i enforcing"],
        ],
        "severity": "HIGH",
        "category": "selinux",
    },
    "2.1.1": {
        "title": "Services: Ensure NIS Client is not installed",
        "description": "Ensure NIS Client is not installed",
        "commands": [
            ["dpkg -l nis 2>/dev/null | grep -v '^un'"],
        ],
        "severity": "HIGH",
        "category": "services",
    },
    "2.1.2": {
        "title": "Services: Ensure rsh client is not installed",
        "description": "Ensure rsh client is not installed",
        "commands": [
            ["dpkg -l rsh-client 2>/dev/null | grep -v '^un'"],
        ],
        "severity": "HIGH",
        "category": "services",
    },
    "2.1.3": {
        "title": "Services: Ensure talk client is not installed",
        "description": "Ensure talk client is not installed",
        "commands": [
            ["dpkg -l talk 2>/dev/null | grep -v '^un'"],
        ],
        "severity": "MEDIUM",
        "category": "services",
    },
    "2.2.1": {
        "title": "Services: Ensure time synchronization is in use",
        "description": "Ensure NTP or chrony is configured",
        "commands": [
            ["which ntpd 2>/dev/null || which chronyd 2>/dev/null"],
        ],
        "severity": "MEDIUM",
        "category": "services",
    },
    "2.2.2": {
        "title": "Services: Ensure X Window System is not installed",
        "description": "Ensure X Window System is not installed",
        "commands": [
            ["dpkg -l xserver-xorg* 2>/dev/null | grep '^ii' | head -1"],
        ],
        "severity": "MEDIUM",
        "category": "services",
    },
    "2.2.3": {
        "title": "Services: Ensure Avahi Server is not installed",
        "description": "Ensure Avahi Server is not installed",
        "commands": [
            ["dpkg -l avahi-daemon 2>/dev/null | grep '^ii'"],
        ],
        "severity": "MEDIUM",
        "category": "services",
    },
    "2.2.4": {
        "title": "Services: Ensure CUPS is not installed",
        "description": "Ensure CUPS is not installed",
        "commands": [
            ["dpkg -l cups 2>/dev/null | grep '^ii'"],
        ],
        "severity": "LOW",
        "category": "services",
    },
    "2.2.5": {
        "title": "Services: Ensure DHCP Server is not installed",
        "description": "Ensure DHCP Server is not installed",
        "commands": [
            ["dpkg -l isc-dhcp-server 2>/dev/null | grep '^ii'"],
        ],
        "severity": "MEDIUM",
        "category": "services",
    },
    "2.2.6": {
        "title": "Services: Ensure LDAP server is not installed",
        "description": "Ensure LDAP server is not installed",
        "commands": [
            ["dpkg -l slapd 2>/dev/null | grep '^ii'"],
        ],
        "severity": "MEDIUM",
        "category": "services",
    },
    "2.2.7": {
        "title": "Services: Ensure NFS is not installed",
        "description": "Ensure NFS is not installed",
        "commands": [
            ["dpkg -l nfs-kernel-server 2>/dev/null | grep '^ii'"],
        ],
        "severity": "MEDIUM",
        "category": "services",
    },
    "2.2.8": {
        "title": "Services: Ensure DNS Server is not installed",
        "description": "Ensure DNS Server is not installed",
        "commands": [
            ["dpkg -l bind9 2>/dev/null | grep '^ii'"],
        ],
        "severity": "MEDIUM",
        "category": "services",
    },
    "2.2.9": {
        "title": "Services: Ensure FTP Server is not installed",
        "description": "Ensure FTP Server is not installed",
        "commands": [
            ["dpkg -l vsftpd 2>/dev/null | grep '^ii'"],
        ],
        "severity": "MEDIUM",
        "category": "services",
    },
    "2.2.10": {
        "title": "Services: Ensure HTTP server is not installed",
        "description": "Ensure HTTP server is not installed unless required",
        "commands": [
            ["dpkg -l apache2 2>/dev/null | grep '^ii'"],
        ],
        "severity": "LOW",
        "category": "services",
    },
    "2.2.11": {
        "title": "Services: Ensure IMAP and POP3 server is not installed",
        "description": "Ensure IMAP and POP3 server is not installed",
        "commands": [
            ["dpkg -l dovecot-imapd 2>/dev/null | grep '^ii'"],
        ],
        "severity": "MEDIUM",
        "category": "services",
    },
    "2.2.12": {
        "title": "Services: Ensure Samba is not installed",
        "description": "Ensure Samba is not installed",
        "commands": [
            ["dpkg -l samba 2>/dev/null | grep '^ii'"],
        ],
        "severity": "MEDIUM",
        "category": "services",
    },
    "2.2.13": {
        "title": "Services: Ensure HTTP Proxy Server is not installed",
        "description": "Ensure Squid proxy is not installed",
        "commands": [
            ["dpkg -l squid 2>/dev/null | grep '^ii'"],
        ],
        "severity": "LOW",
        "category": "services",
    },
    "2.2.14": {
        "title": "Services: Ensure SNMP Server is not installed",
        "description": "Ensure SNMP Server is not installed",
        "commands": [
            ["dpkg -l snmpd 2>/dev/null | grep '^ii'"],
        ],
        "severity": "MEDIUM",
        "category": "services",
    },
    "2.2.15": {
        "title": "Services: Ensure mail transfer agent is configured for local-only",
        "description": "Ensure MTA is configured for local-only mode",
        "commands": [
            ["ss -lntu | grep -E ':25\\s' | grep -v '127.0.0.1' | grep -v '::1'"],
        ],
        "severity": "MEDIUM",
        "category": "services",
    },
    "2.2.16": {
        "title": "Services: Ensure rsync service is not installed",
        "description": "Ensure rsync is not installed",
        "commands": [
            ["dpkg -l rsync 2>/dev/null | grep '^ii'"],
        ],
        "severity": "LOW",
        "category": "services",
    },
    "2.3.1": {
        "title": "Clients: Ensure NIS Client is not installed",
        "description": "Ensure NIS Client is not installed",
        "commands": [
            ["dpkg -l nis 2>/dev/null | grep '^ii'"],
        ],
        "severity": "MEDIUM",
        "category": "clients",
    },
    "3.1.1": {
        "title": "Network: Ensure IP forwarding is disabled",
        "description": "Ensure IP forwarding is disabled",
        "commands": [
            ["sysctl net.ipv4.ip_forward | grep 'net.ipv4.ip_forward = 0'"],
        ],
        "severity": "HIGH",
        "category": "network",
    },
    "3.1.2": {
        "title": "Network: Ensure packet redirect sending is disabled",
        "description": "Ensure packet redirect sending is disabled",
        "commands": [
            ["sysctl net.ipv4.conf.all.send_redirects | grep '= 0'"],
        ],
        "severity": "MEDIUM",
        "category": "network",
    },
    "3.2.1": {
        "title": "Network: Ensure source routed packets are not accepted",
        "description": "Ensure source routed packets are not accepted",
        "commands": [
            ["sysctl net.ipv4.conf.all.accept_source_route | grep '= 0'"],
        ],
        "severity": "MEDIUM",
        "category": "network",
    },
    "3.2.2": {
        "title": "Network: Ensure ICMP redirects are not accepted",
        "description": "Ensure ICMP redirects are not accepted",
        "commands": [
            ["sysctl net.ipv4.conf.all.accept_redirects | grep '= 0'"],
        ],
        "severity": "MEDIUM",
        "category": "network",
    },
    "3.2.3": {
        "title": "Network: Ensure secure ICMP redirects are not accepted",
        "description": "Ensure secure ICMP redirects are not accepted",
        "commands": [
            ["sysctl net.ipv4.conf.all.secure_redirects | grep '= 0'"],
        ],
        "severity": "MEDIUM",
        "category": "network",
    },
    "3.2.4": {
        "title": "Network: Ensure suspicious packets are logged",
        "description": "Ensure suspicious packets are logged",
        "commands": [
            ["sysctl net.ipv4.conf.all.log_martians | grep '= 1'"],
        ],
        "severity": "LOW",
        "category": "network",
    },
    "3.2.5": {
        "title": "Network: Ensure broadcast ICMP requests are ignored",
        "description": "Ensure broadcast ICMP requests are ignored",
        "commands": [
            ["sysctl net.ipv4.icmp_echo_ignore_broadcasts | grep '= 1'"],
        ],
        "severity": "LOW",
        "category": "network",
    },
    "3.2.6": {
        "title": "Network: Ensure bogus ICMP responses are ignored",
        "description": "Ensure bogus ICMP responses are ignored",
        "commands": [
            ["sysctl net.ipv4.icmp_ignore_bogus_error_responses | grep '= 1'"],
        ],
        "severity": "LOW",
        "category": "network",
    },
    "3.2.7": {
        "title": "Network: Ensure Reverse Path Filtering is enabled",
        "description": "Ensure Reverse Path Filtering is enabled",
        "commands": [
            ["sysctl net.ipv4.conf.all.rp_filter | grep '= 1'"],
        ],
        "severity": "MEDIUM",
        "category": "network",
    },
    "3.2.8": {
        "title": "Network: Ensure TCP SYN Cookies is enabled",
        "description": "Ensure TCP SYN Cookies is enabled",
        "commands": [
            ["sysctl net.ipv4.tcp_syncookies | grep '= 1'"],
        ],
        "severity": "MEDIUM",
        "category": "network",
    },
    "3.3.1": {
        "title": "Network: Ensure IPv6 router advertisements are not accepted",
        "description": "Ensure IPv6 router advertisements are not accepted",
        "commands": [
            ["sysctl net.ipv6.conf.all.accept_ra | grep '= 0'"],
        ],
        "severity": "LOW",
        "category": "network",
    },
    "3.4.1": {
        "title": "Network: Ensure DCCP is disabled",
        "description": "Ensure DCCP is disabled",
        "commands": [
            ["lsmod | grep dccp"],
        ],
        "severity": "LOW",
        "category": "network",
    },
    "3.4.2": {
        "title": "Network: Ensure SCTP is disabled",
        "description": "Ensure SCTP is disabled",
        "commands": [
            ["lsmod | grep sctp"],
        ],
        "severity": "LOW",
        "category": "network",
    },
    "3.4.3": {
        "title": "Network: Ensure RDS is disabled",
        "description": "Ensure RDS is disabled",
        "commands": [
            ["lsmod | grep rds"],
        ],
        "severity": "LOW",
        "category": "network",
    },
    "3.4.4": {
        "title": "Network: Ensure TIPC is disabled",
        "description": "Ensure TIPC is disabled",
        "commands": [
            ["lsmod | grep tipc"],
        ],
        "severity": "LOW",
        "category": "network",
    },
    "4.1.1.1": {
        "title": "Auditing: Ensure auditd is installed",
        "description": "Ensure auditd is installed",
        "commands": [
            ["dpkg -l auditd 2>/dev/null | grep '^ii'"],
        ],
        "severity": "HIGH",
        "category": "audit",
    },
    "4.1.1.2": {
        "title": "Auditing: Ensure auditd service is enabled",
        "description": "Ensure auditd service is enabled",
        "commands": [
            ["systemctl is-enabled auditd 2>/dev/null | grep enabled"],
        ],
        "severity": "HIGH",
        "category": "audit",
    },
    "4.1.2.1": {
        "title": "Auditing: Ensure audit log storage size is configured",
        "description": "Ensure audit log storage size is configured",
        "commands": [
            ["grep '^max_log_file' /etc/audit/auditd.conf 2>/dev/null"],
        ],
        "severity": "MEDIUM",
        "category": "audit",
    },
    "4.1.2.2": {
        "title": "Auditing: Ensure audit logs are not automatically deleted",
        "description": "Ensure audit logs are not automatically deleted",
        "commands": [
            ["grep '^max_log_file_action' /etc/audit/auditd.conf 2>/dev/null | grep -iv 'rotate'"],
        ],
        "severity": "MEDIUM",
        "category": "audit",
    },
    "5.1.1": {
        "title": "Access: Ensure cron daemon is enabled and running",
        "description": "Ensure cron daemon is enabled",
        "commands": [
            ["systemctl is-enabled cron 2>/dev/null | grep enabled"],
        ],
        "severity": "LOW",
        "category": "access",
    },
    "5.1.2": {
        "title": "Access: Ensure permissions on /etc/crontab",
        "description": "Ensure permissions on /etc/crontab are configured",
        "commands": [
            ["stat -c '%a' /etc/crontab 2>/dev/null | grep -E '^[0-7]00$|^[0-7]40$'"],
        ],
        "severity": "MEDIUM",
        "category": "access",
    },
    "5.2.1": {
        "title": "Access: Ensure sudo is installed",
        "description": "Ensure sudo is installed",
        "commands": [
            ["dpkg -l sudo 2>/dev/null | grep '^ii'", "which sudo 2>/dev/null"],
        ],
        "severity": "HIGH",
        "category": "access",
    },
    "5.2.2": {
        "title": "Access: Ensure sudo commands use pty",
        "description": "Ensure sudo commands use pty",
        "commands": [
            ["grep -E '^Defaults\\s+use_pty' /etc/sudoers /etc/sudoers.d/* 2>/dev/null"],
        ],
        "severity": "MEDIUM",
        "category": "access",
    },
    "5.2.3": {
        "title": "Access: Ensure sudo log file exists",
        "description": "Ensure sudo log file exists",
        "commands": [
            ["grep -E '^Defaults\\s+logfile' /etc/sudoers /etc/sudoers.d/* 2>/dev/null"],
        ],
        "severity": "LOW",
        "category": "access",
    },
    "5.3.1": {
        "title": "Access: Ensure SSH MaxAuthTries is set to 4 or less",
        "description": "Ensure SSH MaxAuthTries is <= 4",
        "commands": [
            ["sshd -T 2>/dev/null | grep -i maxauthtries | awk '{print $2}' | awk '$1 <= 4'"],
        ],
        "severity": "MEDIUM",
        "category": "ssh",
    },
    "5.3.2": {
        "title": "Access: Ensure SSH IgnoreRhosts is enabled",
        "description": "Ensure SSH IgnoreRhosts is enabled",
        "commands": [
            ["sshd -T 2>/dev/null | grep -i ignorerhosts | awk '{print $2}' | grep yes"],
        ],
        "severity": "MEDIUM",
        "category": "ssh",
    },
    "5.3.3": {
        "title": "Access: Ensure SSH HostbasedAuthentication is disabled",
        "description": "Ensure SSH HostbasedAuthentication is disabled",
        "commands": [
            ["sshd -T 2>/dev/null | grep -i hostbasedauthentication | awk '{print $2}' | grep no"],
        ],
        "severity": "MEDIUM",
        "category": "ssh",
    },
    "5.3.4": {
        "title": "Access: Ensure SSH PermitEmptyPasswords is disabled",
        "description": "Ensure SSH PermitEmptyPasswords is disabled",
        "commands": [
            ["sshd -T 2>/dev/null | grep -i permitemptypasswords | awk '{print $2}' | grep no"],
        ],
        "severity": "HIGH",
        "category": "ssh",
    },
    "5.3.5": {
        "title": "Access: Ensure SSH PermitUserEnvironment is disabled",
        "description": "Ensure SSH PermitUserEnvironment is disabled",
        "commands": [
            ["sshd -T 2>/dev/null | grep -i permituserenvironment | awk '{print $2}' | grep no"],
        ],
        "severity": "MEDIUM",
        "category": "ssh",
    },
    "5.3.6": {
        "title": "Access: Ensure SSH Protocol is set to 2",
        "description": "Ensure SSH Protocol is set to 2",
        "commands": [
            ["sshd -T 2>/dev/null | grep -i protocol | awk '{print $2}' | grep 2"],
        ],
        "severity": "HIGH",
        "category": "ssh",
    },
    "5.3.7": {
        "title": "Access: Ensure SSH X11Forwarding is disabled",
        "description": "Ensure SSH X11Forwarding is disabled",
        "commands": [
            ["sshd -T 2>/dev/null | grep -i x11forwarding | awk '{print $2}' | grep no"],
        ],
        "severity": "MEDIUM",
        "category": "ssh",
    },
    "5.3.8": {
        "title": "Access: Ensure SSH warning banner is configured",
        "description": "Ensure SSH Banner is configured",
        "commands": [
            ["sshd -T 2>/dev/null | grep -i banner | awk '{print $2}' | grep -v none"],
        ],
        "severity": "LOW",
        "category": "ssh",
    },
    "5.4.1": {
        "title": "Access: Ensure password creation requirements are configured",
        "description": "Ensure password creation requirements are configured",
        "commands": [
            ["grep -E '^minlen|^minclass' /etc/security/pwquality.conf 2>/dev/null"],
        ],
        "severity": "MEDIUM",
        "category": "passwords",
    },
    "5.4.2": {
        "title": "Access: Ensure lockout for failed password attempts is configured",
        "description": "Ensure lockout for failed password attempts is configured",
        "commands": [
            ["grep -E 'deny=|unlock_time=' /etc/security/faillock.conf 2>/dev/null"],
        ],
        "severity": "MEDIUM",
        "category": "passwords",
    },
    "5.4.5": {
        "title": "Access: Ensure default user umask is 027 or more restrictive",
        "description": "Ensure default user umask is 027 or more restrictive",
        "commands": [
            ["grep -E '^UMASK\\s+027' /etc/login.defs 2>/dev/null"],
        ],
        "severity": "MEDIUM",
        "category": "passwords",
    },
    "5.5.1": {
        "title": "Access: Ensure password expiration is 365 days or less",
        "description": "Ensure password expiration is 365 days or less",
        "commands": [
            ["grep -E '^PASS_MAX_DAYS\\s+[0-9]+' /etc/login.defs 2>/dev/null | awk '$2 <= 365'"],
        ],
        "severity": "MEDIUM",
        "category": "passwords",
    },
    "5.5.2": {
        "title": "Access: Ensure minimum days between password changes is 7 or more",
        "description": "Ensure minimum days between password changes is 7 or more",
        "commands": [
            ["grep -E '^PASS_MIN_DAYS\\s+[0-9]+' /etc/login.defs 2>/dev/null | awk '$2 >= 7'"],
        ],
        "severity": "MEDIUM",
        "category": "passwords",
    },
    "5.5.3": {
        "title": "Access: Ensure password expiration warning days is 7 or more",
        "description": "Ensure password expiration warning days is 7 or more",
        "commands": [
            ["grep -E '^PASS_WARN_AGE\\s+[0-9]+' /etc/login.defs 2>/dev/null | awk '$2 >= 7'"],
        ],
        "severity": "LOW",
        "category": "passwords",
    },
    "5.6": {
        "title": "Access: Ensure root login is restricted to system console",
        "description": "Ensure root login is restricted",
        "commands": [
            ["grep -E '^auth\\s+required\\s+pam_securetty.so' /etc/pam.d/login 2>/dev/null"],
        ],
        "severity": "MEDIUM",
        "category": "access",
    },
    "6.1.1": {
        "title": "Permissions: Audit system file permissions",
        "description": "Audit system file permissions",
        "commands": [
            ["dpkg --verify 2>/dev/null | head -5"],
        ],
        "severity": "MEDIUM",
        "category": "permissions",
    },
    "6.1.2": {
        "title": "Permissions: Ensure permissions on /etc/passwd",
        "description": "Ensure /etc/passwd permissions are 644 or more restrictive",
        "commands": [
            ["stat -c '%a' /etc/passwd 2>/dev/null | grep -E '^[0-6][0-4][0-4]$'"],
        ],
        "severity": "MEDIUM",
        "category": "permissions",
    },
    "6.1.3": {
        "title": "Permissions: Ensure permissions on /etc/shadow",
        "description": "Ensure /etc/shadow permissions are 000 or 640",
        "commands": [
            ["stat -c '%a' /etc/shadow 2>/dev/null | grep -E '^0$|^[0-6]40$'"],
        ],
        "severity": "HIGH",
        "category": "permissions",
    },
    "6.1.4": {
        "title": "Permissions: Ensure permissions on /etc/group",
        "description": "Ensure /etc/group permissions are 644 or more restrictive",
        "commands": [
            ["stat -c '%a' /etc/group 2>/dev/null | grep -E '^[0-6][0-4][0-4]$'"],
        ],
        "severity": "MEDIUM",
        "category": "permissions",
    },
    "6.1.5": {
        "title": "Permissions: Ensure permissions on /etc/gshadow",
        "description": "Ensure /etc/gshadow permissions are 000 or 640",
        "commands": [
            ["stat -c '%a' /etc/gshadow 2>/dev/null | grep -E '^0$|^[0-6]40$'"],
        ],
        "severity": "HIGH",
        "category": "permissions",
    },
    "6.1.6": {
        "title": "Permissions: Ensure permissions on /etc/passwd-",
        "description": "Ensure /etc/passwd- permissions are 644 or more restrictive",
        "commands": [
            ["stat -c '%a' /etc/passwd- 2>/dev/null | grep -E '^[0-6][0-4][0-4]$'"],
        ],
        "severity": "MEDIUM",
        "category": "permissions",
    },
    "6.1.7": {
        "title": "Permissions: Ensure permissions on /etc/shadow-",
        "description": "Ensure /etc/shadow- permissions are 000 or 640",
        "commands": [
            ["stat -c '%a' /etc/shadow- 2>/dev/null | grep -E '^0$|^[0-6]40$'"],
        ],
        "severity": "HIGH",
        "category": "permissions",
    },
    "6.2.1": {
        "title": "Users: Ensure accounts in /etc/passwd use shadowed passwords",
        "description": "Ensure accounts in /etc/passwd use shadowed passwords",
        "commands": [
            ["awk -F: '($2 != \"x\") {print}' /etc/passwd 2>/dev/null"],
        ],
        "severity": "HIGH",
        "category": "users",
    },
    "6.2.2": {
        "title": "Users: Ensure password fields are not empty",
        "description": "Ensure password fields are not empty",
        "commands": [
            ["awk -F: '($2 == \"\") {print}' /etc/shadow 2>/dev/null"],
        ],
        "severity": "CRITICAL",
        "category": "users",
    },
    "6.2.3": {
        "title": "Users: Ensure all groups in /etc/passwd exist in /etc/group",
        "description": "Ensure all groups in /etc/passwd exist in /etc/group",
        "commands": [
            ["for gid in $(awk -F: '{print $4}' /etc/passwd 2>/dev/null); do grep -q :$gid: /etc/group 2>/dev/null || echo \"missing GID $gid\"; done"],
        ],
        "severity": "MEDIUM",
        "category": "users",
    },
    "6.2.4": {
        "title": "Users: Ensure no duplicate UIDs exist",
        "description": "Ensure no duplicate UIDs exist",
        "commands": [
            ["awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort | uniq -d"],
        ],
        "severity": "MEDIUM",
        "category": "users",
    },
    "6.2.5": {
        "title": "Users: Ensure root is the only UID 0 account",
        "description": "Ensure root is the only UID 0 account",
        "commands": [
            ["awk -F: '($3 == 0) {print $1}' /etc/passwd 2>/dev/null | grep -v '^root$'"],
        ],
        "severity": "CRITICAL",
        "category": "users",
    },
    "6.2.6": {
        "title": "Users: Ensure root PATH integrity",
        "description": "Ensure root PATH integrity",
        "commands": [
            ["echo $PATH | grep -E '^\\.:|:\\.'"],
        ],
        "severity": "HIGH",
        "category": "users",
    },
    "6.2.7": {
        "title": "Users: Ensure all users' home directories exist",
        "description": "Ensure all users' home directories exist",
        "commands": [
            ["awk -F: '($3 >= 1000) {system(\"test -d \" $6)}' /etc/passwd 2>/dev/null"],
        ],
        "severity": "MEDIUM",
        "category": "users",
    },
    "6.2.8": {
        "title": "Users: Ensure users' home directories permissions are 750 or more restrictive",
        "description": "Ensure users' home directories permissions are 750 or more restrictive",
        "commands": [
            ["awk -F: '($3 >= 1000) {system(\"stat -c \\\"%a\\\" \" $6)}' /etc/passwd 2>/dev/null | grep -vE '^[0-7][0-5]0$'"],
        ],
        "severity": "MEDIUM",
        "category": "users",
    },
    "6.2.9": {
        "title": "Users: Ensure users own their home directories",
        "description": "Ensure users own their home directories",
        "commands": [
            ["awk -F: '($3 >= 1000) {system(\"stat -c \\\"%U\\\" \" $6)}' /etc/passwd 2>/dev/null"],
        ],
        "severity": "MEDIUM",
        "category": "users",
    },
    "6.2.10": {
        "title": "Users: Ensure users' dot files are not group or world writable",
        "description": "Ensure users' dot files are not group or world writable",
        "commands": [
            ["awk -F: '($3 >= 1000) {system(\"find \" $6 \" -name \\\".*\\\" -perm /022 -maxdepth 1\")}' /etc/passwd 2>/dev/null"],
        ],
        "severity": "MEDIUM",
        "category": "users",
    },
    "6.2.11": {
        "title": "Users: Ensure no users have .netrc files",
        "description": "Ensure no users have .netrc files",
        "commands": [
            ["awk -F: '($3 >= 1000) {system(\"test -f \" $6 \"/.netrc && echo \" $1)}' /etc/passwd 2>/dev/null"],
        ],
        "severity": "MEDIUM",
        "category": "users",
    },
    "6.2.12": {
        "title": "Users: Ensure no users have .forward files",
        "description": "Ensure no users have .forward files",
        "commands": [
            ["awk -F: '($3 >= 1000) {system(\"test -f \" $6 \"/.forward && echo \" $1)}' /etc/passwd 2>/dev/null"],
        ],
        "severity": "LOW",
        "category": "users",
    },
}

CIS_CHECKS_WINDOWS: Dict[str, Dict[str, Any]] = {
    "1.1.1": {
        "title": "Password Policy: Enforce password history",
        "description": "Ensure 'Enforce password history' is set to 24 or more passwords",
        "command": "net accounts | findstr /i 'password history'",
        "severity": "MEDIUM",
        "category": "password_policy",
    },
    "1.1.2": {
        "title": "Password Policy: Maximum password age",
        "description": "Ensure 'Maximum password age' is set to 60 or fewer days",
        "command": "net accounts | findstr /i 'Maximum password age'",
        "severity": "MEDIUM",
        "category": "password_policy",
    },
    "1.1.3": {
        "title": "Password Policy: Minimum password age",
        "description": "Ensure 'Minimum password age' is set to 1 or more days",
        "command": "net accounts | findstr /i 'Minimum password age'",
        "severity": "MEDIUM",
        "category": "password_policy",
    },
    "1.1.4": {
        "title": "Password Policy: Minimum password length",
        "description": "Ensure 'Minimum password length' is set to 14 or more characters",
        "command": "net accounts | findstr /i 'Minimum password length'",
        "severity": "HIGH",
        "category": "password_policy",
    },
    "2.2.1": {
        "title": "Account Lockout: Lockout duration",
        "description": "Ensure 'Account lockout duration' is set to 15 or more minutes",
        "command": "net accounts | findstr /i 'lockout duration'",
        "severity": "MEDIUM",
        "category": "lockout_policy",
    },
    "2.2.2": {
        "title": "Account Lockout: Lockout threshold",
        "description": "Ensure 'Account lockout threshold' is set to 5 or fewer invalid attempts",
        "command": "net accounts | findstr /i 'lockout threshold'",
        "severity": "HIGH",
        "category": "lockout_policy",
    },
    "2.2.3": {
        "title": "Account Lockout: Reset lockout counter",
        "description": "Ensure 'Reset account lockout counter after' is set to 15 or more minutes",
        "command": "net accounts | findstr /i 'lockout observation window'",
        "severity": "MEDIUM",
        "category": "lockout_policy",
    },
    "9.1.1": {
        "title": "Windows Firewall: Domain profile",
        "description": "Ensure Windows Firewall is enabled for Domain profile",
        "command": "netsh advfirewall show domainprofile | findstr /i State",
        "severity": "HIGH",
        "category": "firewall",
    },
    "9.1.2": {
        "title": "Windows Firewall: Private profile",
        "description": "Ensure Windows Firewall is enabled for Private profile",
        "command": "netsh advfirewall show privateprofile | findstr /i State",
        "severity": "HIGH",
        "category": "firewall",
    },
    "9.1.3": {
        "title": "Windows Firewall: Public profile",
        "description": "Ensure Windows Firewall is enabled for Public profile",
        "command": "netsh advfirewall show publicprofile | findstr /i State",
        "severity": "HIGH",
        "category": "firewall",
    },
    "18.1.1": {
        "title": "LAPS: Ensure LAPS is installed",
        "description": "Ensure 'Local Administrator Password Solution (LAPS)' is installed",
        "command": "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS /v LocalAccountTokenFilterPolicy 2>nul",
        "severity": "HIGH",
        "category": "laps",
    },
    "18.3.1": {
        "title": "UAC: Admin Approval Mode",
        "description": "Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is enabled",
        "command": "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v FilterAdministratorToken 2>nul",
        "severity": "HIGH",
        "category": "uac",
    },
    "18.3.2": {
        "title": "UAC: Behavior of the elevation prompt",
        "description": "Ensure 'User Account Control: Behavior of the elevation prompt for administrators' is set",
        "command": "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorAdmin 2>nul",
        "severity": "MEDIUM",
        "category": "uac",
    },
    "18.3.3": {
        "title": "UAC: Detect application installations",
        "description": "Ensure 'User Account Control: Detect application installations and prompt for elevation' is enabled",
        "command": "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableInstallerDetection 2>nul",
        "severity": "MEDIUM",
        "category": "uac",
    },
    "18.3.4": {
        "title": "UAC: Run all administrators in Admin Approval Mode",
        "description": "Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is enabled",
        "command": "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA 2>nul",
        "severity": "HIGH",
        "category": "uac",
    },
    "18.3.5": {
        "title": "UAC: Virtualize file and registry write failures",
        "description": "Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is enabled",
        "command": "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableVirtualization 2>nul",
        "severity": "LOW",
        "category": "uac",
    },
    "18.4.1": {
        "title": "MSS: Safe DLL search mode",
        "description": "Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode' is enabled",
        "command": "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager /v SafeDllSearchMode 2>nul",
        "severity": "HIGH",
        "category": "system",
    },
    "18.4.2": {
        "title": "MSS: AutoAdminLogon",
        "description": "Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon' is disabled",
        "command": "reg query HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon /v AutoAdminLogon 2>nul",
        "severity": "HIGH",
        "category": "system",
    },
    "18.5.1": {
        "title": "Auditing: Audit account logon events",
        "description": "Ensure 'Audit Account Logon Events' is set to 'Success and Failure'",
        "command": "auditpol /get /subcategory:\"Credential Validation\" 2>nul",
        "severity": "HIGH",
        "category": "audit",
    },
    "18.5.2": {
        "title": "Auditing: Audit account management",
        "description": "Ensure 'Audit Account Management' is set to 'Success and Failure'",
        "command": "auditpol /get /subcategory:\"User Account Management\" 2>nul",
        "severity": "HIGH",
        "category": "audit",
    },
    "18.5.3": {
        "title": "Auditing: Audit process creation",
        "description": "Ensure 'Audit Process Creation' is set to 'Success and Failure'",
        "command": "auditpol /get /subcategory:\"Process Creation\" 2>nul",
        "severity": "MEDIUM",
        "category": "audit",
    },
    "18.5.4": {
        "title": "Auditing: Audit security group management",
        "description": "Ensure 'Audit Security Group Management' is set to 'Success and Failure'",
        "command": "auditpol /get /subcategory:\"Security Group Management\" 2>nul",
        "severity": "MEDIUM",
        "category": "audit",
    },
    "18.5.5": {
        "title": "Auditing: Audit other logon/logoff events",
        "description": "Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'",
        "command": "auditpol /get /subcategory:\"Other Logon/Logoff Events\" 2>nul",
        "severity": "MEDIUM",
        "category": "audit",
    },
    "18.8.1": {
        "title": "BitLocker: Ensure BitLocker is enabled",
        "description": "Ensure BitLocker Drive Encryption is enabled for all drives",
        "command": "manage-bde -status 2>nul | findstr /i 'Protection On'",
        "severity": "HIGH",
        "category": "encryption",
    },
    "18.8.2": {
        "title": "Windows Defender: Ensure real-time monitoring is enabled",
        "description": "Ensure Windows Defender real-time monitoring is enabled",
        "command": "powershell -Command \"Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled\"",
        "severity": "HIGH",
        "category": "defender",
    },
    "18.8.3": {
        "title": "Windows Defender: Ensure signature updates are up to date",
        "description": "Ensure Windows Defender signature updates are up to date",
        "command": "powershell -Command \"Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated\"",
        "severity": "MEDIUM",
        "category": "defender",
    },
    "18.9.1": {
        "title": "Remote Desktop: Ensure RDP is disabled",
        "description": "Ensure Remote Desktop is disabled if not required",
        "command": "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server /v fDenyTSConnections 2>nul",
        "severity": "HIGH",
        "category": "remote_desktop",
    },
}


class CISBenchmark:
    def __init__(self, queue: Queue, hostname: str, scan_interval: int = 86400):
        self.queue = queue
        self.hostname = hostname
        self.scan_interval = scan_interval
        self._stop = False
        self._system = platform.system()

    def _run_shell_command(self, command: str) -> Tuple[bool, str]:
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=15
            )
            output = (result.stdout + result.stderr).strip()
            success = result.returncode == 0
            return success, output
        except subprocess.TimeoutExpired:
            return False, "TIMEOUT"
        except Exception as e:
            return False, str(e)

    def _run_check(self, check_id: str, check: Dict[str, Any]) -> Dict[str, Any]:
        if self._system == "Windows":
            success, output = self._run_shell_command(check["command"])
            passed = not success if check.get("inverse", False) else success
        else:
            passed = False
            output = ""
            commands = check.get("commands", [])
            for cmd_group in commands:
                for cmd in cmd_group if isinstance(cmd_group, list) else [cmd_group]:
                    success, cmd_output = self._run_shell_command(cmd)
                    if success:
                        passed = True
                        output = cmd_output[:500]
                        break
                if passed:
                    break

        return {
            "id": check_id,
            "title": check.get("title", ""),
            "description": check.get("description", ""),
            "severity": check.get("severity", "MEDIUM"),
            "category": check.get("category", ""),
            "passed": passed,
            "output": output[:500],
            "host": self.hostname,
            "platform": self._system,
        }

    def run_scan(self) -> List[Dict[str, Any]]:
        checks = CIS_CHECKS_LINUX if self._system != "Windows" else CIS_CHECKS_WINDOWS
        results = []
        for check_id, check in checks.items():
            if self._stop:
                break
            try:
                result = self._run_check(check_id, check)
                results.append(result)
                if result["severity"] in ("HIGH", "CRITICAL") and not result["passed"]:
                    self._emit_event(result)
            except Exception as e:
                log.warning("CIS check %s failed: %s", check_id, e)
        return results

    def _emit_event(self, result: Dict[str, Any]):
        from datetime import datetime, timezone
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": self.hostname,
            "source": "cis_benchmark",
            "log_type": "cis",
            "severity": result["severity"],
            "message": f"CIS FAIL: {result['id']} - {result['title']}: {result['description']}",
            "metadata": {
                "cis_check_id": result["id"],
                "cis_check_title": result["title"],
                "cis_severity": result["severity"],
                "cis_category": result["category"],
                "cis_passed": result["passed"],
                "cis_output": result["output"],
                "platform": self._system,
                "hostname": self.hostname,
            },
        }
        self.queue.put(event)

    def start(self):
        self.run_scan()

    def stop(self):
        self._stop = True