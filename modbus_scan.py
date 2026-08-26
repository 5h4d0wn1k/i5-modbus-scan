#!/usr/bin/env python3
"""Modbus Scanner - TCP/RTU scanning, function code enumeration, coil/register reading, fingerprinting."""

import socket
import struct
import argparse
import sys
import time
from collections import OrderedDict


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
            self.sock.close()
            self.sock = None

    def _next_tid(self):
        self.transaction_id = (self.transaction_id + 1) & 0xFFFF
        return self.transaction_id

    def send_raw(self, function_code, data=b""):
        tid = self._next_tid()
        pdu = struct.pack(">BB", self.unit_id, function_code) + data
        mbap = struct.pack(">HHH", tid, 0, len(pdu))
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
            "data": body[1:] if is_error else body[1:],
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
        return self.send_raw(0x01, data)

    def read_discrete_inputs(self, address, count):
        data = struct.pack(">HH", address, count)
        return self.send_raw(0x02, data)

    def read_holding_registers(self, address, count):
        data = struct.pack(">HH", address, count)
        return self.send_raw(0x03, data)

    def read_input_registers(self, address, count):
        data = struct.pack(">HH", address, count)
        return self.send_raw(0x04, data)

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

    def read_write_multiple_registers(self, read_addr, read_count, write_addr, write_values):
        wc = len(write_values)
        wbc = wc * 2
        wdata = b"".join(struct.pack(">H", v & 0xFFFF) for v in write_values)
        data = struct.pack(">HHHHB", read_addr, read_count, write_addr, wc, wbc) + wdata
        return self.send_raw(0x17, data)


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
        1: "Illegal Function",
        2: "Illegal Data Address",
        3: "Illegal Data Value",
        4: "Server Device Failure",
        5: "Acknowledge",
        6: "Server Device Busy",
        8: "Memory Parity Error",
        0x0A: "Gateway Path Unavailable",
        0x0B: "Gateway Target Failed",
    }

    def __init__(self, host, port=502, unit_id=1, timeout=3):
        self.host = host
        self.port = port
        self.unit_id = unit_id
        self.timeout = timeout
        self.mb = ModbusTCP(host, port, timeout)
        self.mb.unit_id = unit_id

    def scan_function_codes(self):
        print(f"[*] Scanning function codes on {self.host}:{self.port} (unit={self.unit_id})")
        results = {}
        for fc, name in self.FUNCTION_CODES.items():
            try:
                self.mb.connect()
                resp = self.mb.send_raw(fc, b"\x00\x00\x00\x01")
                self.mb.close()
                if resp:
                    status = "ILLEGAL" if resp["is_error"] else "SUPPORTED"
                    exc = ""
                    if resp["is_error"]:
                        exc = self.EXCEPTION_CODES.get(resp["exception_code"], f"Unknown({resp['exception_code']})")
                    results[fc] = {"name": name, "status": status, "exception": exc}
                    marker = "+" if status == "SUPPORTED" else "-"
                    print(f"  [{marker}] 0x{fc:02X} {name}: {status} {exc}")
            except Exception as e:
                self.mb.close()
                results[fc] = {"name": name, "status": "ERROR", "exception": str(e)}
                print(f"  [-] 0x{fc:02X} {name}: ERROR ({e})")
            time.sleep(0.1)
        return results

    def read_registers(self, fc, address, count):
        try:
            self.mb.connect()
            if fc == 0x01:
                resp = self.mb.read_coils(address, count)
            elif fc == 0x02:
                resp = self.mb.read_discrete_inputs(address, count)
            elif fc == 0x03:
                resp = self.mb.read_holding_registers(address, count)
            elif fc == 0x04:
                resp = self.mb.read_input_registers(address, count)
            else:
                self.mb.close()
                return None
            self.mb.close()
            return resp
        except Exception as e:
            self.mb.close()
            return {"is_error": True, "exception_code": 0, "data": str(e).encode()}

    def fingerprint(self):
        info = {"vendor": "Unknown", "protocol": "Modbus/TCP"}
        resp = self.read_registers(0x03, 0, 4)
        if resp and not resp["is_error"] and len(resp["data"]) >= 8:
            regs = struct.unpack(">" + "H" * (len(resp["data"]) // 2), resp["data"])
            info["registers"] = list(regs)
        resp2 = self.mb.send_raw(0x11, b"")
        if resp2 and not resp2["is_error"]:
            info["server_id"] = resp2["data"].decode("utf-8", errors="ignore").strip()
        resp3 = self.mb.send_raw(0x08, struct.pack(">HH", 0x0000, 0x0000))
        if resp3 and not resp3["is_error"]:
            info["diagnostics"] = True
        return info

    def enum_coils(self, start=0, count=100):
        print(f"[*] Enumerating coils at {start}-{start + count - 1}")
        resp = self.read_registers(0x01, start, count)
        if resp and not resp["is_error"]:
            bits = []
            for byte in resp["data"]:
                for i in range(8):
                    if len(bits) < count:
                        bits.append(bool(byte & (1 << i)))
            for i, val in enumerate(bits):
                print(f"  Coil {start + i}: {'ON' if val else 'OFF'}")
            return bits
        print("  [!] Failed to read coils")
        return None

    def enum_registers(self, fc, start=0, count=10):
        label = {0x03: "Holding", 0x04: "Input"}.get(fc, "Unknown")
        print(f"[*] Reading {label} registers at {start}-{start + count - 1}")
        resp = self.read_registers(fc, start, count)
        if resp and not resp["is_error"]:
            regs = struct.unpack(">" + "H" * (len(resp["data"]) // 2), resp["data"])
            for i, val in enumerate(regs):
                print(f"  Register {start + i}: {val} (0x{val:04X})")
            return list(regs)
        print("  [!] Failed to read registers")
        return None


def main():
    parser = argparse.ArgumentParser(description="Modbus Scanner")
    parser.add_argument("host", nargs="?", help="Target host")
    parser.add_argument("-p", "--port", type=int, default=502, help="Modbus port (default 502)")
    parser.add_argument("-u", "--unit", type=int, default=1, help="Unit ID (default 1)")
    parser.add_argument("-t", "--timeout", type=int, default=3, help="Timeout in seconds")
    parser.add_argument("--scan-fc", action="store_true", help="Scan function codes")
    parser.add_argument("--read-coils", nargs=2, type=int, metavar=("ADDR", "COUNT"), help="Read coils")
    parser.add_argument("--read-holding", nargs=2, type=int, metavar=("ADDR", "COUNT"), help="Read holding registers")
    parser.add_argument("--read-input", nargs=2, type=int, metavar=("ADDR", "COUNT"), help="Read input registers")
    parser.add_argument("--fingerprint", action="store_true", help="Fingerprint device")
    args = parser.parse_args()

    if not args.host:
        parser.print_help()
        return

    print(f"=== Modbus Scanner v1.0 ===")
    print(f"Target: {args.host}:{args.port} Unit: {args.unit}\n")

    scanner = ModbusScanner(args.host, args.port, args.unit, args.timeout)

    if args.scan_fc:
        scanner.scan_function_codes()
        print()
    if args.read_coils:
        scanner.enum_coils(args.read_coils[0], args.read_coils[1])
        print()
    if args.read_holding:
        scanner.enum_registers(0x03, args.read_holding[0], args.read_holding[1])
        print()
    if args.read_input:
        scanner.enum_registers(0x04, args.read_input[0], args.read_input[1])
        print()
    if args.fingerprint:
        print("[*] Fingerprinting device...")
        info = scanner.fingerprint()
        for k, v in info.items():
            print(f"  {k}: {v}")
        print()

    if not any([args.scan_fc, args.read_coils, args.read_holding, args.read_input, args.fingerprint]):
        parser.print_help()


if __name__ == "__main__":
    main()
