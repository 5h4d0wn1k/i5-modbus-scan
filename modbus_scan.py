#!/usr/bin/env python3
"""
I5 - Modbus Scanner
Real Modbus TCP master (raw frames) with read/write coils+registers, unit-id
scan, function-code scanning — plus a loopback mock Modbus/TCP slave so
everything runs and tests offline. Standard-library only.
"""

import socket
import struct
import argparse
import sys
import os
import json
import threading
import time
from collections import OrderedDict


MODBUS_TCP_PORT = 502


class ModbusTCP:
    def __init__(self, host, port=502, timeout=3):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.transaction_id = 0
        self.unit_id = 1

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def _next_tid(self):
        self.transaction_id = (self.transaction_id + 1) & 0xFFFF
        return self.transaction_id

    def send_raw(self, function_code, data=b""):
        tid = self._next_tid()
        pdu = struct.pack(">BB", self.unit_id, function_code) + data
        mbap = struct.pack(">HHH", tid, 0, len(pdu))
        if not self.sock:
            self.connect()
        self.sock.sendall(mbap + pdu)
        return self._recv_response()

    def _recv_response(self):
        header = self._recv_exact(7)
        if not header:
            return None
        tid, proto, length, unit = struct.unpack(">HHHB", header)
        body = self._recv_exact(length - 1)
        if not body:
            return None
        fc = body[0]
        is_error = bool(fc & 0x80)
        return {
            "tid": tid,
            "unit": unit,
            "function_code": fc & 0x7F,
            "is_error": is_error,
            "exception_code": body[1] if is_error else 0,
            "data": body[1:],
            "raw": body,
        }

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def read_coils(self, address, count):
        data = struct.pack(">HH", address, count)
        resp = self.send_raw(0x01, data)
        return self._strip_byte_count(resp)

    def read_discrete_inputs(self, address, count):
        data = struct.pack(">HH", address, count)
        resp = self.send_raw(0x02, data)
        return self._strip_byte_count(resp)

    def read_holding_registers(self, address, count):
        data = struct.pack(">HH", address, count)
        resp = self.send_raw(0x03, data)
        return self._strip_byte_count(resp)

    def read_input_registers(self, address, count):
        data = struct.pack(">HH", address, count)
        resp = self.send_raw(0x04, data)
        return self._strip_byte_count(resp)

    def _strip_byte_count(self, resp):
        """Remove the byte_count byte from a read response's data field."""
        if resp and not resp.get("is_error") and resp.get("data") is not None:
            resp["data"] = bytes(resp["data"][1:])
        return resp

    def write_single_coil(self, address, value):
        data = struct.pack(">HH", address, 0xFF00 if value else 0x0000)
        return self.send_raw(0x05, data)

    def write_single_register(self, address, value):
        data = struct.pack(">HH", address, value & 0xFFFF)
        return self.send_raw(0x06, data)

    def write_multiple_coils(self, address, values):
        count = len(values)
        byte_count = (count + 7) // 8
        coil_data = b""
        for i in range(0, count, 8):
            byte_val = 0
            for j in range(8):
                if i + j < count and values[i + j]:
                    byte_val |= 1 << j
            coil_data += struct.pack("B", byte_val)
        data = struct.pack(">HHB", address, count, byte_count) + coil_data
        return self.send_raw(0x0F, data)

    def write_multiple_registers(self, address, values):
        count = len(values)
        byte_count = count * 2
        reg_data = b"".join(struct.pack(">H", v & 0xFFFF) for v in values)
        data = struct.pack(">HHB", address, count, byte_count) + reg_data
        return self.send_raw(0x10, data)

    def mask_write_register(self, address, and_mask, or_mask):
        data = struct.pack(">HHH", address, and_mask, or_mask)
        return self.send_raw(0x16, data)

    def read_write_multiple_registers(self, read_addr, read_count,
                                      write_addr, write_values):
        wc = len(write_values)
        wbc = wc * 2
        wdata = b"".join(struct.pack(">H", (v & 0xFFFF) if isinstance(v, int) else 0)
                         for v in write_values)
        data = struct.pack(">HHHHB", read_addr, read_count, write_addr, wc, wbc) + wdata
        return self.send_raw(0x17, data)


class MockModbusSlave:
    """Loopback Modbus/TCP slave that serves a fixed coil/register image."""

    COILS = 0x0000
    DISCRETE_INPUTS = 0x2000
    HOLDING_REGS = 0x1000
    INPUT_REGS = 0x3000
    MAX_READ = 125
    MAX_WRITE_REG = 123
    MAX_WRITE_COIL = 1968

    def __init__(self, host="127.0.0.1", port=0, unit_ids=(1,)):
        self.host = host
        self.port = port
        self.unit_ids = unit_ids
        self.sock = None
        self._thread = None
        self.running = False
        self.coils = [False] * 64
        self.discrete = [True] * 64
        self.holding = [0x0000] * 64
        for i in range(0, 64, 2):
            self.holding[i] = i
        self.input = [0x0000] * 64
        for i in range(64):
            self.input[i] = i * 2 + 1

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]
        self.running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self.port

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def _accept_loop(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
                conn.settimeout(2.0)
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _recv_exact(self, conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _handle(self, conn):
        try:
            while True:
                header = self._recv_exact(conn, 7)
                if not header:
                    break
                tid, proto, length, unit = struct.unpack(">HHHB", header)
                pdu = self._recv_exact(conn, length - 1)
                if pdu is None:
                    break
                if unit not in self.unit_ids:
                    # Non-existent unit: silent drop (real Modbus behavior)
                    continue
                response = self._process_pdu(tid, unit, pdu)
                conn.sendall(response)
        except (socket.timeout, OSError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _wrap(self, tid, unit, pdu):
        # PDU over TCP = unit(1) + FC + data; MBAP length counts unit + PDU
        length = len(pdu) + 1
        mbap = struct.pack(">HHH", tid, 0, length)
        return mbap + struct.pack(">B", unit) + pdu

    def _send_error(self, conn, tid, unit, fc, exc):
        pdu = struct.pack(">BB", fc | 0x80, exc)
        conn.sendall(self._wrap(tid, unit, pdu))

    def _process_pdu(self, tid, unit, pdu):
        fc = pdu[0]
        args = pdu[1:]
        try:
            if fc == 0x01:
                return self._read_bits(tid, unit, args, self.coils, "coil")
            elif fc == 0x02:
                return self._read_bits(tid, unit, args, self.discrete, "discrete")
            elif fc == 0x03:
                return self._read_regs(tid, unit, args, self.holding)
            elif fc == 0x04:
                return self._read_regs(tid, unit, args, self.input)
            elif fc == 0x05:
                return self._write_single_coil(tid, unit, args)
            elif fc == 0x06:
                return self._write_single_reg(tid, unit, args)
            elif fc == 0x0F:
                return self._write_multi_coils(tid, unit, args)
            elif fc == 0x10:
                return self._write_multi_regs(tid, unit, args)
            elif fc == 0x11:
                pdu2 = struct.pack(">B", 0x11) + struct.pack(">B", 3) + b"LAB"
                return self._wrap(tid, unit, pdu2)
            elif fc == 0x08:
                sub, data = struct.unpack(">HH", args[:4])
                pdu2 = struct.pack(">BHH", 0x08, sub, data)
                return self._wrap(tid, unit, pdu2)
            elif fc == 0x07:
                status = sum(1 for c in self.coils if c) & 0xFF
                pdu2 = struct.pack(">BB", 0x07, status)
                return self._wrap(tid, unit, pdu2)
            else:
                return self._wrap(tid, unit, struct.pack(">BB", fc | 0x80, 0x01))
        except (struct.error, IndexError):
            return self._wrap(tid, unit, struct.pack(">BB", fc | 0x80, 0x02))

    def _read_bits(self, tid, unit, args, store, kind):
        addr, count = struct.unpack(">HH", args[:4])
        if count > self.MAX_READ or addr + count > len(store):
            fc = (0x01 | 0x80) if kind == "coil" else (0x02 | 0x80)
            return self._wrap(tid, unit, struct.pack(">BB", fc, 0x02))
        byte_count = (count + 7) // 8
        out = [0] * byte_count
        for i in range(count):
            if store[addr + i]:
                byte_idx = i // 8
                bit_idx = i % 8
                out[byte_idx] |= (1 << bit_idx)
        pdu = struct.pack(">BB", 0x01 if kind == "coil" else 0x02, byte_count) + bytes(out)
        return self._wrap(tid, unit, pdu)

    def _read_regs(self, tid, unit, args, store):
        addr, count = struct.unpack(">HH", args[:4])
        if count > self.MAX_READ or addr + count > len(store):
            exc = (0x03 | 0x80) if store is self.holding else (0x04 | 0x80)
            return self._wrap(tid, unit, struct.pack(">BB", exc, 0x02))
        byte_count = count * 2
        data = b"".join(struct.pack(">H", v & 0xFFFF) for v in store[addr:addr + count])
        pdu = struct.pack(">BB", 0x03 if store is self.holding else 0x04, byte_count) + data
        return self._wrap(tid, unit, pdu)

    def _write_single_coil(self, tid, unit, args):
        addr, val = struct.unpack(">HH", args[:4])
        if addr >= len(self.coils):
            return self._wrap(tid, unit, struct.pack(">BB", 0x05 | 0x80, 0x02))
        if val == 0xFF00:
            self.coils[addr] = True
        elif val == 0x0000:
            self.coils[addr] = False
        else:
            return self._wrap(tid, unit, struct.pack(">BB", 0x05 | 0x80, 0x03))
        pdu = struct.pack(">BHH", 0x05, addr, val)
        return self._wrap(tid, unit, pdu)

    def _write_single_reg(self, tid, unit, args):
        addr, val = struct.unpack(">HH", args[:4])
        if addr >= len(self.holding):
            return self._wrap(tid, unit, struct.pack(">BB", 0x06 | 0x80, 0x02))
        self.holding[addr] = val & 0xFFFF
        pdu = struct.pack(">BHH", 0x06, addr, val & 0xFFFF)
        return self._wrap(tid, unit, pdu)

    def _write_multi_coils(self, tid, unit, args):
        addr, count, byte_count = struct.unpack(">HHB", args[:5])
        data = args[5:5 + byte_count]
        if addr + count > len(self.coils):
            return self._wrap(tid, unit, struct.pack(">BB", 0x0F | 0x80, 0x02))
        for i in range(count):
            byte_idx = i // 8
            bit_idx = i % 8
            self.coils[addr + i] = bool(data[byte_idx] & (1 << bit_idx)) if byte_idx < len(data) else False
        pdu = struct.pack(">BHH", 0x0F, addr, count)
        return self._wrap(tid, unit, pdu)

    def _write_multi_regs(self, tid, unit, args):
        addr, count, byte_count = struct.unpack(">HHB", args[:5])
        data = args[5:5 + byte_count]
        if addr + count > len(self.holding):
            return self._wrap(tid, unit, struct.pack(">BB", 0x10 | 0x80, 0x02))
        for i in range(count):
            self.holding[addr + i] = struct.unpack(">H", data[i * 2:i * 2 + 2])[0]
        pdu = struct.pack(">BHH", 0x10, addr, count)
        return self._wrap(tid, unit, pdu)


class ModbusScanner:
    FUNCTION_CODES = OrderedDict([
        (0x01, "Read Coils"),
        (0x02, "Read Discrete Inputs"),
        (0x03, "Read Holding Registers"),
        (0x04, "Read Input Registers"),
        (0x05, "Write Single Coil"),
        (0x06, "Write Single Register"),
        (0x07, "Read Exception Status"),
        (0x08, "Diagnostics"),
        (0x0B, "Get Comm Event Counter"),
        (0x0C, "Get Comm Event Log"),
        (0x0F, "Write Multiple Coils"),
        (0x10, "Write Multiple Registers"),
        (0x11, "Report Server ID"),
        (0x16, "Mask Write Register"),
        (0x17, "Read/Write Multiple Registers"),
        (0x18, "Read FIFO Queue"),
    ])

    EXCEPTION_CODES = {
        1: "Illegal Function", 2: "Illegal Data Address",
        3: "Illegal Data Value", 4: "Server Device Failure",
        5: "Acknowledge", 6: "Server Device Busy",
        8: "Memory Parity Error", 0x0A: "Gateway Path Unavailable",
        0x0B: "Gateway Target Failed",
    }

    def __init__(self, host, port=502, unit_id=1, timeout=3):
        self.host = host
        self.port = port
        self.unit_id = unit_id
        self.timeout = timeout
        self.mb = ModbusTCP(host, port, timeout)
        self.mb.unit_id = unit_id

    def scan_function_codes(self, silent=False):
        results = {}
        for fc, name in self.FUNCTION_CODES.items():
            try:
                self.mb.close()
                self.mb.unit_id = self.unit_id
                resp = self.mb.send_raw(fc, b"\x00\x00\x00\x01")
                was_err = resp and resp["is_error"]
                exc = ""
                if was_err:
                    exc = self.EXCEPTION_CODES.get(resp["exception_code"],
                                                   "Unknown(%d)" % resp["exception_code"])
                status = "ILLEGAL" if was_err else "SUPPORTED"
                results[fc] = {"name": name, "status": status, "exception": exc}
                if not silent:
                    marker = "+" if status == "SUPPORTED" else "-"
                    print("  [%s] 0x%02X %s: %s %s" % (marker, fc, name, status, exc))
            except Exception as e:
                self.mb.close()
                results[fc] = {"name": name, "status": "ERROR", "exception": str(e)}
                if not silent:
                    print("  [-] 0x%02X %s: ERROR (%s)" % (fc, name, e))
        return results

    def read_registers(self, fc, address, count):
        try:
            self.mb.close()
            self.mb.unit_id = self.unit_id
            if fc == 0x01:
                resp = self.mb.read_coils(address, count)
            elif fc == 0x02:
                resp = self.mb.read_discrete_inputs(address, count)
            elif fc == 0x03:
                resp = self.mb.read_holding_registers(address, count)
            elif fc == 0x04:
                resp = self.mb.read_input_registers(address, count)
            else:
                return None
            self.mb.close()
            return resp
        except Exception as e:
            self.mb.close()
            return {"is_error": True, "exception_code": 0, "data": str(e).encode()}

    def scan_unit_ids(self, start=0, end=255):
        """Scan unit range against the slave; return responsive IDs."""
        found = []
        for uid in range(start, end + 1):
            try:
                self.mb.close()
                self.mb.unit_id = uid
                resp = self.mb.send_raw(0x03, struct.pack(">HH", 0, 1))
                if resp:
                    found.append(uid)
            except (socket.timeout, OSError):
                continue
        self.mb.close()
        return found

    def fingerprint(self):
        info = {"vendor": "Unknown", "protocol": "Modbus/TCP"}
        self.mb.close()
        self.mb.unit_id = self.unit_id
        try:
            resp = self.read_registers(0x03, 0, 4)
            if resp and not resp["is_error"] and len(resp["data"]) >= 8:
                regs = struct.unpack(">" + "H" * (len(resp["data"]) // 2), resp["data"])
                info["registers"] = list(regs)
            self.mb.close()
            self.mb.unit_id = self.unit_id
            resp2 = self.mb.send_raw(0x11, b"")
            if resp2 and not resp2["is_error"]:
                info["server_id"] = resp2["data"].decode("utf-8", errors="ignore").strip()
            self.mb.close()
            self.mb.unit_id = self.unit_id
            resp3 = self.mb.send_raw(0x08, struct.pack(">HH", 0x0000, 0x0000))
            if resp3 and not resp3["is_error"]:
                info["diagnostics"] = True
        except (socket.timeout, OSError) as e:
            info["error"] = str(e)
        self.mb.close()
        return info

    def enum_demo(self):
        """Full read/write cycle against a slave for demo output."""
        out = {"reads": [], "writes": []}
        r = self.read_registers(0x03, 0, 4)
        regs = [r["data"][i:i + 2] for i in range(0, len(r["data"]), 2)]
        vals = [struct.unpack(">H", rp)[0] for rp in regs] if not r["is_error"] else []
        if vals:
            out["reads"].append({"fc": "0x03", "regs": vals})
            print("[+] Read holding regs 0-3: %s" % vals)
        c = self.read_registers(0x01, 0, 8)
        if c and not c["is_error"]:
            bits = [bool(b & (1 << i)) for b in c["data"] for i in range(8)][:8]
            out["reads"].append({"fc": "0x01", "coils": [int(x) for x in bits]})
            print("[+] Read coils 0-7: %s" % bits)
        self.mb.close()
        self.mb.unit_id = self.unit_id
        wr = self.mb.write_single_register(5, 0xABCD)
        if wr and not wr["is_error"]:
            out["writes"].append({"fc": "0x06", "reg5": 0xABCD})
            print("[+] Write reg 5 = 0xABCD -> echoed")
        self.mb.close()
        self.mb.unit_id = self.unit_id
        wc = self.mb.write_single_coil(3, True)
        if wc and not wc["is_error"]:
            out["writes"].append({"fc": "0x05", "coil3": True})
            print("[+] Write coil 3 = ON -> echoed")
        self.mb.close()
        self.mb.unit_id = self.unit_id
        rd = self.mb.read_holding_registers(5, 1)
        if rd and not rd["is_error"]:
            v = struct.unpack(">H", rd["data"])[0]
            out["writes"].append({"fc": "0x03", "reg5_after": v})
            print("[+] Read back reg 5 = 0x%04X" % v)
        self.mb.close()
        return out


def start_lab_slave(port=0, unit_ids=(1,), host="127.0.0.1"):
    slave = MockModbusSlave(host, port, unit_ids)
    slave.start()
    return slave


def run_demo(host="127.0.0.1", port=0, report_dir="reports"):
    print("=== I5 - Modbus Scanner (Offline Demo) ===")
    slave = MockModbusSlave(host, port, (1,))
    actual_port = slave.start()
    print("[+] Mock Modbus/TCP slave on 127.0.0.1:%d (unit=1)" % actual_port)

    results = {"host": host, "port": actual_port, "records": {}}
    try:
        scanner = ModbusScanner(host, actual_port, unit_id=1, timeout=2)
        print("\n[*] Unit-ID scan (1..4)...")
        units = scanner.scan_unit_ids(0, 4)
        results["units"] = units
        print("[+] Responsive unit IDs: %s" % units)

        print("\n[*] Function-code scan (1..4)...")
        codes = scanner.scan_function_codes(silent=True)
        supported = [f for f, r in codes.items() if r["status"] == "SUPPORTED"]
        if codes:
            for fc in sorted(codes):
                r = codes[fc]
                print("  [%s] 0x%02X %s: %s %s" % (
                    "+" if r["status"] == "SUPPORTED" else "-", fc,
                    r["name"], r["status"], r["exception"]))
        results["function_codes"] = codes

        print("\n[*] Register/coil read-write cycle...")
        cycle = scanner.enum_demo()
        results["cycle"] = cycle

        print("\n[*] Fingerprint...")
        fp = scanner.fingerprint()
        for k, v in fp.items():
            print("  %s: %s" % (k, v))
        results["fingerprint"] = fp

        # Byte-exact frame check
        print("\n[*] Byte-exact frame verification...")
        mb = ModbusTCP(host, actual_port, timeout=2)
        mb.unit_id = 1
        mb.connect()
        mb.transaction_id = 0x0007
        req = mb.send_raw(0x03, struct.pack(">HH", 0, 2))
        evidence = {"socket": None}
        if req and not req["is_error"]:
            print("[+] Read holding 0..1 -> %s" % req["data"].hex())
            results["frame_data"] = req["data"].hex()
        mb.close()

    except Exception as e:
        results["error"] = str(e)
        print("[-] Demo error: %s" % e)
    finally:
        slave.stop()

    os.makedirs(report_dir, exist_ok=True)
    rpath = os.path.join(report_dir, "i5_demo_report.json")
    with open(rpath, "w") as f:
        json.dump(results, f, indent=2)
    print("\n[+] Report: %s" % rpath)
    print("[+] Demo complete — exit 0")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="I5 - Modbus Scanner (educational, authorized use only)",
        epilog="Example: python3 modbus_scan.py 127.0.0.1 -p 502 --scan-fc",
    )
    parser.add_argument("--demo", action="store_true",
                        help="Run offline demo with loopback mock Modbus slave")
    parser.add_argument("host", nargs="?", default="127.0.0.1",
                        help="Target host (default 127.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=502,
                        help="Modbus port (default 502)")
    parser.add_argument("-u", "--unit", type=int, default=1,
                        help="Unit ID (default 1)")
    parser.add_argument("-t", "--timeout", type=int, default=3,
                        help="Timeout in seconds")
    parser.add_argument("--scan-fc", action="store_true",
                        help="Scan function codes")
    parser.add_argument("--read-coils", nargs=2, type=int,
                        metavar=("ADDR", "COUNT"), help="Read coils")
    parser.add_argument("--read-holding", nargs=2, type=int,
                        metavar=("ADDR", "COUNT"), help="Read holding registers")
    parser.add_argument("--read-input", nargs=2, type=int,
                        metavar=("ADDR", "COUNT"), help="Read input registers")
    parser.add_argument("--write-reg", nargs=2, type=int,
                        metavar=("ADDR", "VALUE"), help="Write single register")
    parser.add_argument("--write-coil", nargs=2, type=int,
                        metavar=("ADDR", "VALUE"), help="Write single coil (0/1)")
    parser.add_argument("--scan-units", action="store_true",
                        help="Scan unit IDs")
    parser.add_argument("--fingerprint", action="store_true",
                        help="Fingerprint device")
    parser.add_argument("--json", action="store_true",
                        help="Write JSON report to reports/")
    parser.add_argument("--report-dir", default="reports",
                        help="Report output directory (default reports/)")
    args = parser.parse_args()

    if args.demo:
        sys.exit(run_demo(report_dir=args.report_dir))

    if not any([args.scan_fc, args.read_coils, args.read_holding,
                args.read_input, args.write_reg, args.write_coil,
                args.scan_units, args.fingerprint]):
        parser.print_help()
        sys.exit(0)

    print("=== Modbus Scanner v2.0 ===")
    print("Target: %s:%d Unit: %d\n" % (args.host, args.port, args.unit))

    scanner = ModbusScanner(args.host, args.port, args.unit, args.timeout)
    results = {"host": args.host, "port": args.port, "unit": args.unit}

    if args.scan_fc:
        print("[*] Scanning function codes...")
        codes = scanner.scan_function_codes()
        results["function_codes"] = {hex(k): v for k, v in codes.items()}

    if args.read_coils:
        print("[*] Reading coils...")
        resp = scanner.read_registers(0x01, args.read_coils[0], args.read_coils[1])
        if resp and not resp["is_error"]:
            n = args.read_coils[1]
            bits = []
            for byte in resp["data"]:
                for i in range(8):
                    if len(bits) < n:
                        bits.append(bool(byte & (1 << i)))
            for i, val in enumerate(bits):
                print("  Coil %d: %s" % (args.read_coils[0] + i, "ON" if val else "OFF"))
            results["coils"] = [int(x) for x in bits]
        else:
            print("  [!] Failed to read coils")
            results["coils_error"] = resp["is_error"] if resp else True

    if args.read_holding or args.read_input:
        fc = 0x03 if args.read_holding else 0x04
        addr, count = (args.read_holding or args.read_input)
        label = "Holding" if fc == 0x03 else "Input"
        print("[*] Reading %s registers (%d..%d)..." % (label, addr, addr + count - 1))
        resp = scanner.read_registers(fc, addr, count)
        if resp and not resp["is_error"]:
            regs = struct.unpack(">" + "H" * (len(resp["data"]) // 2), resp["data"])
            for i, val in enumerate(regs):
                print("  Register %d: %d (0x%04X)" % (addr + i, val, val))
            results[label.lower() + "_regs"] = list(regs)
        else:
            print("  [!] Failed to read %s registers" % label)
            results[label.lower() + "_regs_error"] = True

    if args.write_reg and args.host and args.port:
        print("[*] Writing register %d = %d..." % (args.write_reg[0], args.write_reg[1]))
        scanner.mb.close()
        scanner.mb.unit_id = args.unit
        resp = scanner.mb.write_single_register(args.write_reg[0], args.write_reg[1])
        if resp:
            print("  [+] Echo: 0x%04X" % args.write_reg[1] if not resp["is_error"] else "  [-] %s" % resp)
        scanner.mb.close()

    if args.write_coil and args.host and args.port:
        print("[*] Writing coil %d = %d..." % (args.write_coil[0], args.write_coil[1]))
        scanner.mb.close()
        scanner.mb.unit_id = args.unit
        resp = scanner.mb.write_single_coil(args.write_coil[0], bool(args.write_coil[1]))
        if resp:
            print("  [+] Echo: 0x%04X" % (0xFF00 if args.write_coil[1] else 0x0000)
                  if not resp["is_error"] else "  [-] %s" % resp)
        scanner.mb.close()

    if args.scan_units:
        print("[*] Scanning unit IDs 0..255...")
        units = scanner.scan_unit_ids(0, 255)
        print("[+] Responsive units: %s" % units)
        results["units"] = units

    if args.fingerprint:
        print("[*] Fingerprinting device...")
        info = scanner.fingerprint()
        for k, v in info.items():
            print("  %s: %s" % (k, v))
        results["fingerprint"] = info

    if args.json:
        os.makedirs(args.report_dir, exist_ok=True)
        rpath = os.path.join(args.report_dir, "i5_report.json")
        with open(rpath, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print("\n[+] Report: %s" % rpath)

    sys.exit(0)


if __name__ == "__main__":
    main()