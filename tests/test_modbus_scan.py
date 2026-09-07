#!/usr/bin/env python3
"""Deterministic offline tests for I5 - Modbus scanner (loopback mock slave)."""

import json
import os
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import modbus_scan as i5
from modbus_scan import (
    ModbusTCP, ModbusScanner, MockModbusSlave, start_lab_slave,
    run_demo,
)


class TestMbapFrame(unittest.TestCase):
    def test_mbap_header_constants(self):
        """MBAP header: TID(2) + ProtoID=0x0000(2) + Length(2) + UnitID(1)"""
        slave = MockModbusSlave("127.0.0.1", 0, (1,))
        slave.start()
        try:
            mb = ModbusTCP("127.0.0.1", slave.port, timeout=2)
            mb.unit_id = 1
            mb.connect()
            mb.transaction_id = 0x0010
            resp = mb.send_raw(0x03, struct.pack(">HH", 0, 2))
            mb.close()
            self.assertIsNotNone(resp)
            self.assertFalse(resp["is_error"])
            # _next_tid() increments from 0x10 -> 0x11 before sending
            self.assertEqual(resp["tid"], 0x0011)
            self.assertEqual(resp["unit"], 1)
            self.assertEqual(resp["function_code"], 0x03)
        finally:
            slave.stop()

    def test_mbap_proto_id_zero(self):
        slave = MockModbusSlave("127.0.0.1", 0, (1,))
        slave.start()
        try:
            mb = ModbusTCP("127.0.0.1", slave.port, timeout=2)
            mb.unit_id = 1
            mb.connect()
            # Send raw bytes and verify the proto ID is 0x0000
            tid = 0x0022
            fc = 0x01
            data = struct.pack(">HH", 0, 4)
            pdu = struct.pack(">BB", mb.unit_id, fc) + data
            mbap = struct.pack(">HHH", tid, 0, len(pdu))
            mb.sock.sendall(mbap + pdu)
            header = mb._recv_exact(7)
            proto = struct.unpack(">H", header[2:4])[0]
            self.assertEqual(proto, 0)
            mb.close()
        finally:
            slave.stop()


class TestReadCoils(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.slave = MockModbusSlave("127.0.0.1", 0, (1,))
        cls.port = cls.slave.start()
        # Set known coil state: 01010101
        cls.slave.coils[0:8] = [True, False, True, False, True, False, True, False]

    @classmethod
    def tearDownClass(cls):
        cls.slave.stop()

    def test_read_coils_byte_exact(self):
        """Read coils 0-8: byte 0 = 0x55 (0b01010101), byte 1 = 0x00 if only 8 coils."""
        mb = ModbusTCP("127.0.0.1", self.port, timeout=2)
        mb.unit_id = 1
        resp = mb.read_coils(0, 8)
        self.assertIsNotNone(resp)
        self.assertFalse(resp["is_error"])
        self.assertEqual(resp["function_code"], 0x01)
        # Bitmask: coil 0=LSB of byte 0, coil 1=bit1 of byte 0, ...
        # [True,False,True,False,True,False,True,False] = 0x55
        self.assertEqual(resp["data"][0], 0x55)
        mb.close()

    def test_read_coils_across_bytes(self):
        """Coils 0-15: byte0=0x55, byte1=0x00 (all False)."""
        self.slave.coils[8:16] = [False] * 8
        mb = ModbusTCP("127.0.0.1", self.port, timeout=2)
        mb.unit_id = 1
        resp = mb.read_coils(0, 16)
        self.assertEqual(len(resp["data"]), 2)
        self.assertEqual(resp["data"][0], 0x55)
        self.assertEqual(resp["data"][1], 0x00)
        mb.close()


class TestReadHoldingRegisters(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.slave = MockModbusSlave("127.0.0.1", 0, (1,))
        cls.port = cls.slave.start()
        cls.slave.holding[0] = 0xBEEF
        cls.slave.holding[1] = 0xCAFE
        cls.slave.holding[2] = 0x1234
        cls.slave.holding[3] = 0x5678

    @classmethod
    def tearDownClass(cls):
        cls.slave.stop()

    def test_read_holding_4_regs(self):
        mb = ModbusTCP("127.0.0.1", self.port, timeout=2)
        mb.unit_id = 1
        resp = mb.read_holding_registers(0, 4)
        self.assertFalse(resp["is_error"])
        self.assertEqual(len(resp["data"]), 8)  # 4 regs * 2 bytes
        regs = struct.unpack(">4H", resp["data"])
        self.assertEqual(regs, (0xBEEF, 0xCAFE, 0x1234, 0x5678))
        mb.close()


class TestWriteSingleRegister(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.slave = MockModbusSlave("127.0.0.1", 0, (1,))
        cls.port = cls.slave.start()

    @classmethod
    def tearDownClass(cls):
        cls.slave.stop()

    def test_write_and_read_back(self):
        mb = ModbusTCP("127.0.0.1", self.port, timeout=2)
        mb.unit_id = 1
        resp = mb.write_single_register(5, 0xABCD)
        self.assertFalse(resp["is_error"])
        self.assertEqual(resp["function_code"], 0x06)
        mb.close()
        self.assertEqual(self.slave.holding[5], 0xABCD)
        mb2 = ModbusTCP("127.0.0.1", self.port, timeout=2)
        mb2.unit_id = 1
        resp2 = mb2.read_holding_registers(5, 1)
        self.assertFalse(resp2["is_error"])
        v = struct.unpack(">H", resp2["data"])[0]
        self.assertEqual(v, 0xABCD)
        mb2.close()


class TestWriteSingleCoil(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.slave = MockModbusSlave("127.0.0.1", 0, (1,))
        cls.port = cls.slave.start()
        cls.slave.coils[0:8] = [False] * 8

    @classmethod
    def tearDownClass(cls):
        cls.slave.stop()

    def test_write_coil_on_off(self):
        mb = ModbusTCP("127.0.0.1", self.port, timeout=2)
        mb.unit_id = 1
        resp = mb.write_single_coil(3, True)
        self.assertFalse(resp["is_error"])
        mb.close()
        self.assertTrue(self.slave.coils[3])
        mb2 = ModbusTCP("127.0.0.1", self.port, timeout=2)
        mb2.unit_id = 1
        mb2.write_single_coil(3, False)
        self.assertFalse(self.slave.coils[3])
        mb2.close()


class TestExceptionCodes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.slave = MockModbusSlave("127.0.0.1", 0, (1,))
        cls.port = cls.slave.start()

    @classmethod
    def tearDownClass(cls):
        cls.slave.stop()

    def test_illegal_data_address(self):
        mb = ModbusTCP("127.0.0.1", self.port, timeout=2)
        mb.unit_id = 1
        resp = mb.read_holding_registers(1000, 1)
        self.assertTrue(resp["is_error"])
        self.assertEqual(resp["exception_code"], 2)
        mb.close()


class TestUnitIdScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.slave = MockModbusSlave("127.0.0.1", 0, (1,))
        cls.port = cls.slave.start()

    @classmethod
    def tearDownClass(cls):
        cls.slave.stop()

    def test_only_unit_1_responds(self):
        scanner = ModbusScanner("127.0.0.1", self.port, unit_id=1, timeout=1)
        found = scanner.scan_unit_ids(0, 10)
        self.assertIn(1, found)
        self.assertNotIn(2, found)
        self.assertNotIn(3, found)


class TestMultiWrite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.slave = MockModbusSlave("127.0.0.1", 0, (1,))
        cls.port = cls.slave.start()

    @classmethod
    def tearDownClass(cls):
        cls.slave.stop()

    def test_write_multiple_coils(self):
        mb = ModbusTCP("127.0.0.1", self.port, timeout=2)
        mb.unit_id = 1
        resp = mb.write_multiple_coils(0, [True, False, True, True, False, False, True, False])
        self.assertFalse(resp["is_error"])
        self.assertEqual(resp["function_code"], 0x0F)
        mb.close()
        self.assertTrue(self.slave.coils[0])
        self.assertFalse(self.slave.coils[1])
        self.assertTrue(self.slave.coils[2])
        self.assertTrue(self.slave.coils[3])

    def test_write_multiple_registers(self):
        mb = ModbusTCP("127.0.0.1", self.port, timeout=2)
        mb.unit_id = 1
        resp = mb.write_multiple_registers(0, [0x1234, 0x5678])
        self.assertFalse(resp["is_error"])
        self.assertEqual(resp["function_code"], 0x10)
        mb.close()
        self.assertEqual(self.slave.holding[0], 0x1234)
        self.assertEqual(self.slave.holding[1], 0x5678)


class TestDemo(unittest.TestCase):
    def test_demo_exits_zero_with_report(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            rc = run_demo(report_dir=os.path.join(tmp, "reports"))
            self.assertEqual(rc, 0)
            rpath = os.path.join(tmp, "reports", "i5_demo_report.json")
            self.assertTrue(os.path.exists(rpath))
            with open(rpath) as f:
                data = json.load(f)
            self.assertGreaterEqual(len(data.get("units", [])), 1)
            self.assertTrue(data.get("fingerprint"))
            self.assertTrue(data.get("function_codes"))


if __name__ == "__main__":
    unittest.main()