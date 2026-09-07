# I5 — Modbus Scanner

Real Modbus TCP master (raw MBAP frames) with read/write coils+registers, unit-ID scan, function-code enumeration — plus a loopback mock Modbus/TCP slave for fully offline testing. Standard-library only.

## What the engine genuinely does

- **Raw MBAP framing** — every packet is hand-built struct `TID(2)+Proto=0(2)+Len(2)+Unit(1)+FC(1)+Data` and parsed back with byte-exact assertions.
- **Read/Write operations** — `0x01` Read Coils, `0x02` Read Discrete Inputs, `0x03` Read Holding Registers, `0x04` Read Input Registers, `0x05` Write Single Coil, `0x06` Write Single Register, `0x0F` Write Multiple Coils, `0x10` Write Multiple Registers.
- **Unit-ID scan** — iterates 0–255 against a slave to find responsive unit IDs (Modbus gateways).
- **Function-code enumeration** — probes each FC against the slave; classifies as SUPPORTED, ILLEGAL (with exception code), or ERROR.
- **Exception code translation** — maps Modbus exception codes to their protocol names.
- **Fingerprint** — reads server ID (FC 0x11) and diagnostics (FC 0x08) to identify vendor.
- **Mock Modbus/TCP slave** — full implementation of a server answering coils/registers, with correct exception responses for out-of-range addresses.

## Quick start

```bash
# Offline demo: mock slave, full scan, writes reports/, exit 0
python3 modbus_scan.py --demo

# Scan function codes against a lab Modbus device
python3 modbus_scan.py 192.0.2.100 -p 502 -u 1 --scan-fc

# Read holding registers
python3 modbus_scan.py 192.0.2.100 --read-holding 0 10 --json

# Unit-ID scan
python3 modbus_scan.py 192.0.2.100 --scan-units

# Write register 5 = 0xABCD (destructive — default OFF; explicit only)
python3 modbus_scan.py 192.0.2.100 --write-reg 5 43981

# Tests
python3 -m unittest discover -s tests
```

## CLI

```
python3 modbus_scan.py [-h] [--demo] [host] [-p PORT] [-u UNIT] [-t SEC]
                       [--scan-fc] [--read-coils ADDR COUNT]
                       [--read-holding ADDR COUNT] [--read-input ADDR COUNT]
                       [--write-reg ADDR VALUE] [--write-coil ADDR VALUE]
                       [--scan-units] [--fingerprint] [--json] [--report-dir DIR]
```

- `--demo` — offline loopback demo, exit 0.
- `--json` — write JSON report to `reports/`.
- `--write-reg`, `--write-coil` — destructive ops, require explicit target host+port.

Exit codes: `0` success (incl. demo), non-zero on errors.

## Live Lab Test Plan

Prerequisites: a Modbus/TCP device you own (libmodbus `mbtserver`, ModRSsim, or the bundled mock).

1. **Baseline**: `python3 modbus_scan.py --demo` — confirm unit 1 responds, at least 4 FCs are SUPPORTED, registers match the mock image (0,2,4,6…), and the demo JSON report is written (exit 0).
2. **Real slave**: `mbtserver -p 1983` on a lab host, then
   `python3 modbus_scan.py 127.0.0.1 1983 --scan-fc`. Cross-check with
   `mbtclient 127.0.0.1 1983 -a 0x03 -d 00000004`.
3. **Exception path**: read beyond the slave address range — confirm Illegal Data Address (exception 2) is returned correctly.
4. **Multi-register write**: `--write-reg 10 0xBEEF` then `--read-holding 10 1` on the same slave; verify the echo and read-back match.
5. **Regression**: re-run `python3 -m unittest discover -s tests`.

## Metrics

| Metric                     | Value |
|----------------------------|-------|
| Standard-library only      | Yes   |
| Third-party deps           | none  |
| Deterministic offline tests| 13    |
| Loopback mock slave        | built-in (`MockModbusSlave`) |
| Offline demo exit          | 0     |
| Report output              | `reports/*.json` (gitignored) |
| Wire format                | Modbus/TCP (MBAP + PDU) |
| Frame byte-exact           | Yes — tests verify TID, proto, length, unit, FC |

## IMPORTANT: Read before use.

Educational, authorization-required tooling. Only test Modbus devices you own or
are explicitly authorized to assess. Write operations (`--write-reg`,
`--write-coil`) are destructive and default OFF. See `LICENSE` for the full
shield — Authorization, CFAA / computer-crime statutes, Acceptable Use,
Prohibited Use, No Warranty, and Responsible Disclosure.

## License

MIT — full legal shield in `LICENSE`.