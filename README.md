# I5 — Modbus Scanner

Modbus TCP/RTU scanning, function code enumeration, coil/register reading, and device fingerprinting tool.

## Overview

This project implements a Modbus protocol scanner that:
- Scans for supported Modbus function codes
- Reads coils, discrete inputs, and holding/input registers
- Fingerprints Modbus devices via server ID and diagnostics
- Enumerates coil states and register values
- Supports error detection and exception code interpretation

## Features

- **Function Code Scanning**: Identify supported Modbus operations
- **Register Reading**: Read holding and input registers
- **Coil Enumeration**: Read coil states (ON/OFF)
- **Device Fingerprinting**: Extract vendor info via diagnostics
- **Exception Handling**: Interpret Modbus exception responses

## Installation

```bash
# No external dependencies - uses Python standard library only
# Requires Python 3.6+
```

## Usage

```bash
# Scan function codes on Modbus device
python3 modbus_scan.py 192.168.1.100 --scan-fc

# Read holding registers (address 0, count 10)
python3 modbus_scan.py 192.168.1.100 --read-holding 0 10

# Read input registers
python3 modbus_scan.py 192.168.1.100 --read-input 0 10

# Read coils
python3 modbus_scan.py 192.168.1.100 --read-coils 0 50

# Fingerprint device
python3 modbus_scan.py 192.168.1.100 --fingerprint

# Scan with custom unit ID and port
python3 modbus_scan.py 192.168.1.100 -u 2 -p 502 --scan-fc
```

## Example Output

```
=== Modbus Scanner v1.0 ===
Target: 192.168.1.100:502 Unit: 1

[*] Scanning function codes on 192.168.1.100:502 (unit=1)
  [+] 0x01 Read Coils: SUPPORTED
  [+] 0x02 Read Discrete Inputs: SUPPORTED
  [+] 0x03 Read Holding Registers: SUPPORTED
  [+] 0x04 Read Input Registers: SUPPORTED
  [+] 0x05 Write Single Coil: SUPPORTED
  [+] 0x06 Write Single Register: SUPPORTED
  [-] 0x0F Write Multiple Coils: ILLEGAL Illegal Function
  [+] 0x10 Write Multiple Registers: SUPPORTED
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
