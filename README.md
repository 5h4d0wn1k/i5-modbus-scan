> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# I5 — Modbus Scanner

**Modbus/TCP ICS security scanner** by **5h4d0wn1k** for **SCADA assessment**
and industrial-control education: a raw-MBAP Modbus master with coil/register
read-write, unit-ID scanning (0–255), function-code enumeration, exception-code
translation and vendor fingerprinting — plus a loopback mock Modbus/TCP slave
for fully offline testing. Standard-library only.

## Why a Modbus scanner for ICS

Modbus is the least common denominator of industrial control networks — and
frequently exposed with no auth, an open unit namespace and every function
code enabled. This scanner demonstrates how a master enumerates a slave's
register map and supported function codes, the exact operations defenders must
audit (reads you can template, writes you must gate), and how exception
responses leak capability. All write operations default OFF and require an
explicit target, keeping exercises safe for lab rigs. Scope it strictly to
devices you own or hold written authorization to assess — see
[ETHICS.md](ETHICS.md) and [SCOPE.md](SCOPE.md).

## Features

- **Raw MBAP framing** — every packet hand-built as
  `TID(2)+Proto(0)(2)+Len(2)+Unit(1)+FC(1)+Data` and parsed back
  byte-exact (`ModbusTCP`).
- **Read/write operations** — `0x01`/`0x02`/`0x03`/`0x04` reads plus
  `0x05`/`0x06`/`0x0F`/`0x10` single and multi-writes.
- **Function-code enumeration** — probes each FC and classifies SUPPORTED,
  ILLEGAL (with exception code) or ERROR (`scan_function_codes`).
- **Unit-ID scan** — iterates `0–255` to surface responsive gateway unit IDs.
- **Exception translation** — maps Modbus exception codes to protocol names.
- **Fingerprinting** — reads Report Server ID (`0x11`) and diagnostics
  (`0x08`) to identify the vendor.
- **Mock Modbus/TCP slave** — answers coils/registers with correct exception
  responses for out-of-range addresses (`MockModbusSlave`).
- **JSON reports** — write structured findings to `reports/`.

## Quickstart

```bash
# Offline demo: mock slave, full scan, writes reports/, exit 0
python3 modbus_scan.py --demo

# Scan function codes against a lab Modbus device
python3 modbus_scan.py 192.0.2.100 -p 502 -u 1 --scan-fc

# Read holding registers (address 0, count 10)
python3 modbus_scan.py 192.0.2.100 --read-holding 0 10 --json

# Unit-ID scan
python3 modbus_scan.py 192.0.2.100 --scan-units

# Write register 5 = 0xABCD (destructive; explicit target required)
python3 modbus_scan.py 192.0.2.100 --write-reg 5 43981

# Run the test suite (12 deterministic offline tests)
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

- `--demo` — offline loopback demo, exit `0`.
- `--json` — write a JSON report to `reports/`.
- `--write-reg`, `--write-coil` — destructive operations, require an explicit
  target host and port.

Exit codes: `0` on success (including the demo), non-zero on errors.

## Project structure

```
modbus_scan.py      # MBAP framing, scanner engine, mock slave, CLI
tests/              # unittest coverage: wire bytes, ops, exceptions, demo
ETHICS.md           # educational-use policy (read first)
SCOPE.md            # scope and target authorization rules
```

## Documentation

- [ETHICS.md](ETHICS.md) — acceptable and prohibited use.
- [SCOPE.md](SCOPE.md) — authorized target scope.
- [SECURITY.md](SECURITY.md) — responsible disclosure.
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide.

## Contributing

New function-code mappings, register-map fixtures and mock-slave behaviors are
welcome. Open an issue or PR against the default branch; keep contributions
scoped to educational and authorized-use tooling.

## License

MIT — full legal shield in [LICENSE](LICENSE). Educational, authorization-
required software for assessing Modbus/TCP infrastructure you own or are
explicitly permitted to test.