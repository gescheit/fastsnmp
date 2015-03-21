#!/usr/bin/python3
# -*- coding: utf-8 -*-
import unittest
from fastsnmp import snmp_parser


class TestSnmpParser(unittest.TestCase):
    def setUp(self):
        self.target_oid = "1.3.6.1.2.1.2.2.1.2"
        self.target_oid_encoded = bytes([43, 6, 1, 2, 1, 2, 2, 1, 2])

    def test_oid_coder(self):
        oid_encoded = snmp_parser.objectid_encode(self.target_oid)
        self.assertEqual(self.target_oid_encoded, oid_encoded)

    def test_oid_decoder(self):
        oid_decoded = snmp_parser.objectid_decode(self.target_oid_encoded)
        self.assertEqual(self.target_oid, oid_decoded)

if __name__ == "__main__":
    unittest.main()
