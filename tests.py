#!/usr/bin/python3
# -*- coding: utf-8 -*-
import unittest
import pstats
import cProfile
from fastsnmp import snmp_parser


class TestSnmpParser(unittest.TestCase):
    strs = [
        [b'56', b'\x35\x36'],  # str
        [b'\x00\x80\xeaB^7', b'\x00\x80\xea\x42\x5e\x37'],  # bytes
    ]
    ints = [
        [-1, b'\xff'],
        [-136, b'\xff\x78'],
        [-1390, b'\xfa\x92'],
        [4294970001, b'\x01\x00\x00\n\x91'],
    ]
    uints = [
        [0, b'\x00'],
        [1, b'\x01'],
        [2, b'\x02'],
        [128, b'\x00\x80'],
        [256, b'\x01\x00'],
        [4294970001, b'\x01\x00\x00\n\x91'],
        [17179869184, b'\x04\x00\x00\x00\x00'],
        [2568068810643379472, b'\x23\xa3\x9c\xfa\x21\x28\x95\x10'],
        [18446744073709551615, b'\x00\xff\xff\xff\xff\xff\xff\xff\xff'],
        [523160, b'\x07\xfb\x98'],
    ]
    object_ids = [
        ["1.2", b'\x2a'],
        ["1.2.128", b'\x2a\x81\x00'],
        ["1.2.128.128", b'\x2a\x81\x00\x81\x00'],
        ["1.2.256", b'\x2a\x82\x00'],
        ["1.2.65536", b'\x2a\x84\x80\x00'],
        ["1.2.99999", b'\x2a\x86\x8d\x1f'],
        ['1.3.268633409', b'\x2b\x81\x80\x8c\x8a\x41'],
    ]
    tags = [
        [(67, 1), b'\x43'],
    ]
    length = [
        [(15, 1), b'\x0f'],
        # [(127, 2), b'\x81\x7f'],  # long form
        [(127, 1), b'\x7f'],
        [(129, 2), b'\x81\x81'],
        [(1256, 3), b'\x82\x04\xe8'],
    ]

    def test_integer_encode(self):
        for i, enc in self.ints:
            int_encoded = snmp_parser.integer_encode(i)
            self.assertEqual(int_encoded, enc)

    def test_integer_decode(self):
        for i, enc in self.ints:
            int_decoded = snmp_parser.integer_decode(enc)
            self.assertEqual(int_decoded, i)

    def test_counter64_encode(self):
        for i, enc in self.uints:
            int_encoded = snmp_parser.uinteger_encode(i)
            self.assertEqual(int_encoded, enc)

    def test_counter64_decode(self):
        for i, enc in self.uints:
            int_decoded = snmp_parser.uinteger_decode(enc)
            self.assertEqual(int_decoded, i)

    def test_str_decode(self):
        for i, enc in self.strs:
            str_decoded = snmp_parser.octetstring_decode(enc)
            self.assertEqual(str_decoded, i)

    def test_oid_encoder(self):
        for str_oid, enc in self.object_ids:
            oid_encoded = snmp_parser.objectid_encode(str_oid)
            self.assertEqual(enc, bytes(oid_encoded))

    def test_oid_decoder(self):
        for str_oid, enc in self.object_ids:
            oid_decoded = snmp_parser.objectid_decode(enc)
            self.assertEqual(str_oid, oid_decoded)

    def test_tag_decode(self):
        for tag, enc in self.tags:
            tag_decoded = snmp_parser.tag_decode(enc)
            self.assertEqual(tag, tag_decoded)

    def test_length_decode(self):
        for length, enc in self.length:
            length_decoded = snmp_parser.length_decode(enc)
            self.assertEqual(length, length_decoded)
            length_encoded = snmp_parser.length_encode(length[0])
            self.assertEqual(length_encoded, enc)

    def test_decode(self):
        msg = b'0\x82\x06W\x02\x01\x01\x04\x04test\xa2\x82\x06J\x02\x02\x1f\xc1\x02\x01\x00\x02\x01\x000\x82\x06<0"' \
              b'\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\x02\x81\xb0\x80\x88L\x04\x10port-channel11010\x13\x06\x0e+\x06' \
              b'\x01\x02\x01\x02\x02\x01\x0e\x81\xb0\x80\x88LA\x01\x000\x13\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\r' \
              b'\x81\xb0\x80\x88LA\x01\x000\x1a\x06\x0f+\x06\x01\x02\x01\x1f\x01\x01\x01\n\x81\xb0\x80\x88LF\x07\x01' \
              b'\xdd9R\x9b\xd7\xdd0\x18\x06\x0f+\x06\x01\x02\x01\x1f\x01\x01\x01\x0b\x81\xb0\x80\x88LF\x05\'\xb5+\xec' \
              b'\x0b0\x13\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\x14\x81\xb0\x80\x88LA\x01\x000\x1a\x06\x0f+\x06\x01\x02' \
              b'\x01\x1f\x01\x01\x01\x06\x81\xb0\x80\x88LF\x07\x01\xb5\xad\x9b2\x96b0\x13\x06\x0e+\x06\x01\x02\x01\x02' \
              b'\x02\x01\x13\x81\xb0\x80\x88LA\x01\x000\x18\x06\x0f+\x06\x01\x02\x01\x1f\x01\x01\x01\x07\x81\xb0\x80' \
              b'\x88LF\x05\'\xbd\x11\x1d\xa60"\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\x02\x81\xb0\x80\x88M\x04' \
              b'\x10port-channel11020\x13\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\x0e\x81\xb0\x80\x88MA\x01\x000\x13\x06' \
              b'\x0e+\x06\x01\x02\x01\x02\x02\x01\r\x81\xb0\x80\x88MA\x01\x000\x1a\x06\x0f+\x06\x01\x02\x01\x1f\x01' \
              b'\x01\x01\n\x81\xb0\x80\x88MF\x07\x00\xbb\xbf\xe8\xe2\xc7\xef0\x18\x06\x0f+\x06\x01\x02\x01\x1f\x01\x01' \
              b'\x01\x0b\x81\xb0\x80\x88MF\x051\xb5\x7f\xdf"0\x13\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\x14\x81\xb0\x80' \
              b'\x88MA\x01\x000\x1a\x06\x0f+\x06\x01\x02\x01\x1f\x01\x01\x01\x06\x81\xb0\x80\x88MF\x07\x01?*\xaa\x156' \
              b'\x170\x14\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\x13\x81\xb0\x80\x88MA\x02\x07\x860\x18\x06\x0f+\x06\x01' \
              b'\x02\x01\x1f\x01\x01\x01\x07\x81\xb0\x80\x88MF\x055\x8d\x04\xed90"\x06\x0e+\x06\x01\x02\x01\x02\x02\x01' \
              b'\x02\x81\xb0\x80\x88N\x04\x10port-channel11030\x13\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\x0e\x81\xb0\x80' \
              b'\x88NA\x01\x000\x13\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\r\x81\xb0\x80\x88NA\x01\x000\x1a\x06\x0f+\x06' \
              b'\x01\x02\x01\x1f\x01\x01\x01\n\x81\xb0\x80\x88NF\x07\x02h\xe4v\xe0Dz0\x18\x06\x0f+\x06\x01\x02\x01\x1f' \
              b'\x01\x01\x01\x0b\x81\xb0\x80\x88NF\x05&\xa8-l\xbe0\x13\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\x14\x81\xb0' \
              b'\x80\x88NA\x01\x000\x1a\x06\x0f+\x06\x01\x02\x01\x1f\x01\x01\x01\x06\x81\xb0\x80\x88NF\x07\x01\x97' \
              b'\xb5p\xb9\xe2\xe50\x13\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\x13\x81\xb0\x80\x88NA\x01\x000\x18\x06' \
              b'\x0f+\x06\x01\x02\x01\x1f\x01\x01\x01\x07\x81\xb0\x80\x88NF\x05"r\x11\x89\x0f0"\x06\x0e+\x06\x01\x02' \
              b'\x01\x02\x02\x01\x02\x81\xb0\x80\x88O\x04\x10port-channel11040\x13\x06\x0e+\x06\x01\x02\x01\x02\x02' \
              b'\x01\x0e\x81\xb0\x80\x88OA\x01\x000\x13\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\r\x81\xb0\x80\x88OA\x01' \
              b'\x000\x1a\x06\x0f+\x06\x01\x02\x01\x1f\x01\x01\x01\n\x81\xb0\x80\x88OF\x07\x02h\xd6\xc1\xa2\x19\xcf0' \
              b'\x18\x06\x0f+\x06\x01\x02\x01\x1f\x01\x01\x01\x0b\x81\xb0\x80\x88OF\x05\'H\x98w&0\x13\x06\x0e+\x06' \
              b'\x01\x02\x01\x02\x02\x01\x14\x81\xb0\x80\x88OA\x01\x000\x1a\x06\x0f+\x06\x01\x02\x01\x1f\x01\x01\x01' \
              b'\x06\x81\xb0\x80\x88OF\x07\x01\xc1\xc0gn\xcf\x040\x13\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\x13\x81' \
              b'\xb0\x80\x88OA\x01\x000\x18\x06\x0f+\x06\x01\x02\x01\x1f\x01\x01\x01\x07\x81\xb0\x80\x88OF\x05%\r' \
              b'\xe1)\xa00"\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\x02\x81\xb0\x80\x88P\x04\x10port-channel11050\x13' \
              b'\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\x0e\x81\xb0\x80\x88PA\x01\x000\x13\x06\x0e+\x06\x01\x02\x01' \
              b'\x02\x02\x01\r\x81\xb0\x80\x88PA\x01\x000\x1a\x06\x0f+\x06\x01\x02\x01\x1f\x01\x01\x01\n\x81\xb0\x80' \
              b'\x88PF\x07\x015)\xff\x8f\xf5\xab0\x18\x06\x0f+\x06\x01\x02\x01\x1f\x01\x01\x01\x0b\x81\xb0\x80\x88PF' \
              b'\x05Q\x03\xf5=\xe90\x13\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\x14\x81\xb0\x80\x88PA\x01\x000\x1a\x06' \
              b'\x0f+\x06\x01\x02\x01\x1f\x01\x01\x01\x06\x81\xb0\x80\x88PF\x07\x02\x0b\x91\xb5E\xd3k0\x14\x06\x0e+' \
              b'\x06\x01\x02\x01\x02\x02\x01\x13\x81\xb0\x80\x88PA\x02ZX0\x18\x06\x0f+\x06\x01\x02\x01\x1f\x01\x01' \
              b'\x01\x07\x81\xb0\x80\x88PF\x05Q\xa0\xbe\xd6\x810"\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\x02\x81\xb0' \
              b'\x80\x88Q\x04\x10port-channel11060\x13\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\x0e\x81\xb0\x80\x88QA' \
              b'\x01\x000\x13\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\r\x81\xb0\x80\x88QA\x01\x000\x19\x06\x0f+\x06' \
              b'\x01\x02\x01\x1f\x01\x01\x01\n\x81\xb0\x80\x88QF\x06u\x04\xd1:C,0\x18\x06\x0f+\x06\x01\x02\x01' \
              b'\x1f\x01\x01\x01\x0b\x81\xb0\x80\x88QF\x05\x14\x92\xc5\xa8)0\x13\x06\x0e+\x06\x01\x02\x01\x02' \
              b'\x02\x01\x14\x81\xb0\x80\x88QA\x01\x000\x19\x06\x0f+\x06\x01\x02\x01\x1f\x01\x01\x01\x06\x81\xb0' \
              b'\x80\x88QF\x06%\x150\xbb\x05\x960\x13\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\x13\x81\xb0\x80\x88QA' \
              b'\x01\x000\x18\x06\x0f+\x06\x01\x02\x01\x1f\x01\x01\x01\x07\x81\xb0\x80\x88QF\x05\x16\x05!&+0"' \
              b'\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\x02\x81\xb0\x80\x88R\x04\x10port-channel11070\x13\x06\x0e+' \
              b'\x06\x01\x02\x01\x02\x02\x01\x0e\x81\xb0\x80\x88RA\x01\x000\x13\x06\x0e+\x06\x01\x02\x01\x02\x02' \
              b'\x01\r\x81\xb0\x80\x88RA\x01\x000\x1a\x06\x0f+\x06\x01\x02\x01\x1f\x01\x01\x01\n\x81\xb0\x80\x88RF' \
              b'\x07\x02\xae\r\x8c\xaaU\x980\x18\x06\x0f+\x06\x01\x02\x01\x1f\x01\x01\x01\x0b\x81\xb0\x80\x88RF\x05+' \
              b'\xf8lm\xb50\x13\x06\x0e+\x06\x01\x02\x01\x02\x02\x01\x14\x81\xb0\x80\x88RA\x01\x000\x1a\x06\x0f+\x06' \
              b'\x01\x02\x01\x1f\x01\x01\x01\x06\x81\xb0\x80\x88RF\x07\x01\xee\xd7$,\xbb\xce0\x13\x06\x0e+\x06\x01' \
              b'\x02\x01\x02\x02\x01\x13\x81\xb0\x80\x88RA\x01\x000\x18\x06\x0f+\x06\x01\x02\x01\x1f\x01\x01\x01\x07' \
              b'\x81\xb0\x80\x88RF\x05(<i(\xf9'
        encoded = (8129, 0, 0, [['1.3.6.1.2.1.2.2.1.2.369099852', b'port-channel1101'],
                                ['1.3.6.1.2.1.2.2.1.14.369099852', 0],
                                ['1.3.6.1.2.1.2.2.1.13.369099852', 0],
                                ['1.3.6.1.2.1.31.1.1.1.10.369099852', 524713245530077],
                                ['1.3.6.1.2.1.31.1.1.1.11.369099852', 170543279115],
                                ['1.3.6.1.2.1.2.2.1.20.369099852', 0],
                                ['1.3.6.1.2.1.31.1.1.1.6.369099852', 481232214464098],
                                ['1.3.6.1.2.1.2.2.1.19.369099852', 0],
                                ['1.3.6.1.2.1.31.1.1.1.7.369099852', 170675740070],
                                ['1.3.6.1.2.1.2.2.1.2.369099853', b'port-channel1102'],
                                ['1.3.6.1.2.1.2.2.1.14.369099853', 0],
                                ['1.3.6.1.2.1.2.2.1.13.369099853', 0],
                                ['1.3.6.1.2.1.31.1.1.1.10.369099853', 206432920324079],
                                ['1.3.6.1.2.1.31.1.1.1.11.369099853', 213498453794],
                                ['1.3.6.1.2.1.2.2.1.20.369099853', 0],
                                ['1.3.6.1.2.1.31.1.1.1.6.369099853', 350927451403799],
                                ['1.3.6.1.2.1.2.2.1.19.369099853', 1926],
                                ['1.3.6.1.2.1.31.1.1.1.7.369099853', 229999177017],
                                ['1.3.6.1.2.1.2.2.1.2.369099854', b'port-channel1103'],
                                ['1.3.6.1.2.1.2.2.1.14.369099854', 0],
                                ['1.3.6.1.2.1.2.2.1.13.369099854', 0],
                                ['1.3.6.1.2.1.31.1.1.1.10.369099854', 678280409662586],
                                ['1.3.6.1.2.1.31.1.1.1.11.369099854', 166030306494],
                                ['1.3.6.1.2.1.2.2.1.20.369099854', 0],
                                ['1.3.6.1.2.1.31.1.1.1.6.369099854', 448280512815845],
                                ['1.3.6.1.2.1.2.2.1.19.369099854', 0],
                                ['1.3.6.1.2.1.31.1.1.1.7.369099854', 147942639887],
                                ['1.3.6.1.2.1.2.2.1.2.369099855', b'port-channel1104'],
                                ['1.3.6.1.2.1.2.2.1.14.369099855', 0],
                                ['1.3.6.1.2.1.2.2.1.13.369099855', 0],
                                ['1.3.6.1.2.1.31.1.1.1.10.369099855', 678221534337487],
                                ['1.3.6.1.2.1.31.1.1.1.11.369099855', 168721676070],
                                ['1.3.6.1.2.1.2.2.1.20.369099855', 0],
                                ['1.3.6.1.2.1.31.1.1.1.6.369099855', 494507089907460],
                                ['1.3.6.1.2.1.2.2.1.19.369099855', 0],
                                ['1.3.6.1.2.1.31.1.1.1.7.369099855', 159146650016],
                                ['1.3.6.1.2.1.2.2.1.2.369099856', b'port-channel1105'],
                                ['1.3.6.1.2.1.2.2.1.14.369099856', 0],
                                ['1.3.6.1.2.1.2.2.1.13.369099856', 0],
                                ['1.3.6.1.2.1.31.1.1.1.10.369099856', 339929474266539],
                                ['1.3.6.1.2.1.31.1.1.1.11.369099856', 347958754793],
                                ['1.3.6.1.2.1.2.2.1.20.369099856', 0],
                                ['1.3.6.1.2.1.31.1.1.1.6.369099856', 575670392836971],
                                ['1.3.6.1.2.1.2.2.1.19.369099856', 23128],
                                ['1.3.6.1.2.1.31.1.1.1.7.369099856', 350589212289],
                                ['1.3.6.1.2.1.2.2.1.2.369099857', b'port-channel1106'],
                                ['1.3.6.1.2.1.2.2.1.14.369099857', 0],
                                ['1.3.6.1.2.1.2.2.1.13.369099857', 0],
                                ['1.3.6.1.2.1.31.1.1.1.10.369099857', 128663550575404],
                                ['1.3.6.1.2.1.31.1.1.1.11.369099857', 88361773097],
                                ['1.3.6.1.2.1.2.2.1.20.369099857', 0],
                                ['1.3.6.1.2.1.31.1.1.1.6.369099857', 40772942103958],
                                ['1.3.6.1.2.1.2.2.1.19.369099857', 0],
                                ['1.3.6.1.2.1.31.1.1.1.7.369099857', 94575339051],
                                ['1.3.6.1.2.1.2.2.1.2.369099858', b'port-channel1107'],
                                ['1.3.6.1.2.1.2.2.1.14.369099858', 0],
                                ['1.3.6.1.2.1.2.2.1.13.369099858', 0],
                                ['1.3.6.1.2.1.31.1.1.1.10.369099858', 754323171202456],
                                ['1.3.6.1.2.1.31.1.1.1.11.369099858', 188851449269],
                                ['1.3.6.1.2.1.2.2.1.20.369099858', 0],
                                ['1.3.6.1.2.1.31.1.1.1.6.369099858', 544082769001422],
                                ['1.3.6.1.2.1.2.2.1.19.369099858', 0],
                                ['1.3.6.1.2.1.31.1.1.1.7.369099858', 172812216569]])

        msg_decoded = snmp_parser.msg_decode(msg)
        self.assertEqual(encoded, msg_decoded)

    def test_parse_varbind(self):
        result = [['1.2.1.1', 1], ['1.2.2.1', 1], ['1.2.3.1', 1],
                  ['1.2.1.2', 1], ['1.2.2.2', 1], ['1.2.3.2', 1],
                  ['1.2.1.3', 1], ['1.2.2.3', 1], ['1.2.3.3', 1],
                  ['1.2.1.4', 1], ['1.2.2.4', 1], ['1.2.3.4', 1],
                  ]
        main_oids = ('1.2.1', '1.2.2', '1.2.3')
        prev_oids_to_poll = ('1.2.1', '1.2.2', '1.2.3')
        expected_res = [['1.2.1', '1', 1], ['1.2.2', '1', 1], ['1.2.3', '1', 1], ['1.2.1', '2', 1], ['1.2.2', '2', 1],
                        ['1.2.3', '2', 1], ['1.2.1', '3', 1], ['1.2.2', '3', 1], ['1.2.3', '3', 1], ['1.2.1', '4', 1],
                        ['1.2.2', '4', 1], ['1.2.3', '4', 1]]
        expected_oids_to_poll = ('1.2.1.4', '1.2.2.4', '1.2.3.4')
        result, next_oids_to_poll = snmp_parser.parse_varbind(result, main_oids, prev_oids_to_poll)
        self.assertEqual(next_oids_to_poll, expected_oids_to_poll)
        self.assertEqual(result, expected_res)

    def test_parse_varbind2(self):
        # unequal oids len
        result = [['1.2.1.1', 1], ['1.2.2.1', 1], ['1.2.3.1', 1],
                  ['1.2.1.2', 1], ['1.2.2.2', 1], ['1.2.3.2', 1],
                  ['1.2.999.1', 1], ['1.2.2.3', 1], ['1.2.3.3', 1],
                  ['1.2.999.2', 1], ['1.2.2.4', 1], ['1.2.3.4', 1],
                  ]
        main_oids = ('1.2.1', '1.2.2', '1.2.3')
        prev_oids_to_poll = ('1.2.1', '1.2.2', '1.2.3')
        expected_res = [['1.2.1', '1', 1], ['1.2.2', '1', 1], ['1.2.3', '1', 1], ['1.2.1', '2', 1], ['1.2.2', '2', 1],
                        ['1.2.3', '2', 1], ['1.2.2', '3', 1], ['1.2.3', '3', 1], ['1.2.2', '4', 1], ['1.2.3', '4', 1]]
        expected_oids_to_poll = (None, '1.2.2.4', '1.2.3.4')
        result, next_oids_to_poll = snmp_parser.parse_varbind(result, main_oids, prev_oids_to_poll)
        self.assertEqual(next_oids_to_poll, expected_oids_to_poll)
        self.assertEqual(result, expected_res)

    def _test_parse_varbind_perf(self):
        result = []
        for i in range(100):
            for y in range(10):
                result.append(['1.2.%s.%s' % (y, i), i + 3])

        main_oids = tuple(['1.2.%s' % i for i in range(10)])
        oids_to_poll = main_oids
        snmp_parser.parse_varbind(result, main_oids, oids_to_poll)

    def _test_parse_varbind_prof(self):
        cProfile.runctx("for i in range(1000): self._test_parse_varbind_perf()", globals(), locals(), "Profile.prof")

        s = pstats.Stats("Profile.prof")
        s.strip_dirs().sort_stats("time").print_stats()


if __name__ == "__main__":
    unittest.main()
