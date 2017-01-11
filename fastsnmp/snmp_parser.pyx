# cython: nonecheck=False, boundscheck=False, wraparound=False, language_level=3
# cython: c_string_type=str, c_string_encoding=ascii
# cython: profile=True
# adds doc-strings for sphinx
# -*- coding: utf-8 -*-
# based on https://pypi.python.org/pypi/libsnmp/

# X.690
# http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf

import cython
from cpython.tuple cimport PyTuple_New, PyTuple_SET_ITEM
from cpython.int cimport PyInt_FromLong
from cpython.ref cimport Py_INCREF
from libc.stdio cimport sprintf
from libc.string cimport memcpy
from itertools import cycle

DEF MAX_OID_LEN_STR=500

cdef extern from "stdint.h" nogil:
    ctypedef signed int int8_t
    ctypedef signed int int32_t
    ctypedef signed int int64_t
    ctypedef unsigned int uint8_t
    ctypedef unsigned int uint32_t
    ctypedef unsigned int uint64_t

class SNMPException(Exception):
    pass


class VarBindUnpackException(SNMPException):
    pass


class VarBindContentException(SNMPException):
    pass


asnTagClasses = {
    'UNIVERSAL': 0x00,
    'APPLICATION': 0x40,
    'CONTEXT': 0x80,
    'PRIVATE': 0xC0
}

asnTagFormats = {
    'PRIMITIVE': 0x00,
    'CONSTRUCTED': 0x20
}

ASN_TYPES = {
    'Integer': 0x02,
    'OctetString': 0x04,
    'Null': 0x05,
    'ObjectID': 0x06,
    'Sequence': 0x10,
}

ASN_SNMP_APPLICATION = {
    'IPAddress': 0x00,
    'Counter': 0x01,
    'Guage': 0x02,
    'TimeTicks': 0x03,
    'Opaque': 0x04,
}

ASN_SNMP_MSG_TYPES ={
    'Get': 0x00,
    'GetNext': 0x01,
    'Response': 0x02,
    'Set': 0x03,
    'Trap': 0x04,
    'GetBulk': 0x05,
}

# caches
length_cache = {}
length_cache[0] = b'\x00'
length_cache[1] = b'\x01'

# sub id 1 and 2 bytes
# int
cdef struct SID12_ti:
    uint64_t SID1
    uint64_t SID2

# str
cdef struct SID12_t:
    size_t strlen
    char *str

cdef SID12_ti *sid12i = [{'SID1': 0, 'SID2': 0},{'SID1': 0, 'SID2': 1},{'SID1': 0, 'SID2': 2},{'SID1': 0, 'SID2': 3},{'SID1': 0, 'SID2': 4},{'SID1': 0, 'SID2': 5},{'SID1': 0, 'SID2': 6},{'SID1': 0, 'SID2': 7},{'SID1': 0, 'SID2': 8},{'SID1': 0, 'SID2': 9},{'SID1': 0, 'SID2': 10},{'SID1': 0, 'SID2': 11},{'SID1': 0, 'SID2': 12},{'SID1': 0, 'SID2': 13},{'SID1': 0, 'SID2': 14},{'SID1': 0, 'SID2': 15},{'SID1': 0, 'SID2': 16},{'SID1': 0, 'SID2': 17},{'SID1': 0, 'SID2': 18},{'SID1': 0, 'SID2': 19},{'SID1': 0, 'SID2': 20},{'SID1': 0, 'SID2': 21},{'SID1': 0, 'SID2': 22},{'SID1': 0, 'SID2': 23},{'SID1': 0, 'SID2': 24},{'SID1': 0, 'SID2': 25},{'SID1': 0, 'SID2': 26},{'SID1': 0, 'SID2': 27},{'SID1': 0, 'SID2': 28},{'SID1': 0, 'SID2': 29},{'SID1': 0, 'SID2': 30},{'SID1': 0, 'SID2': 31},{'SID1': 0, 'SID2': 32},{'SID1': 0, 'SID2': 33},{'SID1': 0, 'SID2': 34},{'SID1': 0, 'SID2': 35},{'SID1': 0, 'SID2': 36},{'SID1': 0, 'SID2': 37},{'SID1': 0, 'SID2': 38},{'SID1': 0, 'SID2': 39},{'SID1': 1, 'SID2': 0},{'SID1': 1, 'SID2': 1},{'SID1': 1, 'SID2': 2},{'SID1': 1, 'SID2': 3},{'SID1': 1, 'SID2': 4},{'SID1': 1, 'SID2': 5},{'SID1': 1, 'SID2': 6},{'SID1': 1, 'SID2': 7},{'SID1': 1, 'SID2': 8},{'SID1': 1, 'SID2': 9},{'SID1': 1, 'SID2': 10},{'SID1': 1, 'SID2': 11},{'SID1': 1, 'SID2': 12},{'SID1': 1, 'SID2': 13},{'SID1': 1, 'SID2': 14},{'SID1': 1, 'SID2': 15},{'SID1': 1, 'SID2': 16},{'SID1': 1, 'SID2': 17},{'SID1': 1, 'SID2': 18},{'SID1': 1, 'SID2': 19},{'SID1': 1, 'SID2': 20},{'SID1': 1, 'SID2': 21},{'SID1': 1, 'SID2': 22},{'SID1': 1, 'SID2': 23},{'SID1': 1, 'SID2': 24},{'SID1': 1, 'SID2': 25},{'SID1': 1, 'SID2': 26},{'SID1': 1, 'SID2': 27},{'SID1': 1, 'SID2': 28},{'SID1': 1, 'SID2': 29},{'SID1': 1, 'SID2': 30},{'SID1': 1, 'SID2': 31},{'SID1': 1, 'SID2': 32},{'SID1': 1, 'SID2': 33},{'SID1': 1, 'SID2': 34},{'SID1': 1, 'SID2': 35},{'SID1': 1, 'SID2': 36},{'SID1': 1, 'SID2': 37},{'SID1': 1, 'SID2': 38},{'SID1': 1, 'SID2': 39},{'SID1': 2, 'SID2': 0},{'SID1': 2, 'SID2': 1},{'SID1': 2, 'SID2': 2},{'SID1': 2, 'SID2': 3},{'SID1': 2, 'SID2': 4},{'SID1': 2, 'SID2': 5},{'SID1': 2, 'SID2': 6},{'SID1': 2, 'SID2': 7},{'SID1': 2, 'SID2': 8},{'SID1': 2, 'SID2': 9},{'SID1': 2, 'SID2': 10},{'SID1': 2, 'SID2': 11},{'SID1': 2, 'SID2': 12},{'SID1': 2, 'SID2': 13},{'SID1': 2, 'SID2': 14},{'SID1': 2, 'SID2': 15},{'SID1': 2, 'SID2': 16},{'SID1': 2, 'SID2': 17},{'SID1': 2, 'SID2': 18},{'SID1': 2, 'SID2': 19},{'SID1': 2, 'SID2': 20},{'SID1': 2, 'SID2': 21},{'SID1': 2, 'SID2': 22},{'SID1': 2, 'SID2': 23},{'SID1': 2, 'SID2': 24},{'SID1': 2, 'SID2': 25},{'SID1': 2, 'SID2': 26},{'SID1': 2, 'SID2': 27},{'SID1': 2, 'SID2': 28},{'SID1': 2, 'SID2': 29},{'SID1': 2, 'SID2': 30},{'SID1': 2, 'SID2': 31},{'SID1': 2, 'SID2': 32},{'SID1': 2, 'SID2': 33},{'SID1': 2, 'SID2': 34},{'SID1': 2, 'SID2': 35},{'SID1': 2, 'SID2': 36},{'SID1': 2, 'SID2': 37},{'SID1': 2, 'SID2': 38},{'SID1': 2, 'SID2': 39}]
cdef SID12_t *sid12s = [{'str': b'0.0\x00', 'strlen': 3},{'str': b'0.1\x00', 'strlen': 3},{'str': b'0.2\x00', 'strlen': 3},{'str': b'0.3\x00', 'strlen': 3},{'str': b'0.4\x00', 'strlen': 3},{'str': b'0.5\x00', 'strlen': 3},{'str': b'0.6\x00', 'strlen': 3},{'str': b'0.7\x00', 'strlen': 3},{'str': b'0.8\x00', 'strlen': 3},{'str': b'0.9\x00', 'strlen': 3},{'str': b'0.10', 'strlen': 4},{'str': b'0.11', 'strlen': 4},{'str': b'0.12', 'strlen': 4},{'str': b'0.13', 'strlen': 4},{'str': b'0.14', 'strlen': 4},{'str': b'0.15', 'strlen': 4},{'str': b'0.16', 'strlen': 4},{'str': b'0.17', 'strlen': 4},{'str': b'0.18', 'strlen': 4},{'str': b'0.19', 'strlen': 4},{'str': b'0.20', 'strlen': 4},{'str': b'0.21', 'strlen': 4},{'str': b'0.22', 'strlen': 4},{'str': b'0.23', 'strlen': 4},{'str': b'0.24', 'strlen': 4},{'str': b'0.25', 'strlen': 4},{'str': b'0.26', 'strlen': 4},{'str': b'0.27', 'strlen': 4},{'str': b'0.28', 'strlen': 4},{'str': b'0.29', 'strlen': 4},{'str': b'0.30', 'strlen': 4},{'str': b'0.31', 'strlen': 4},{'str': b'0.32', 'strlen': 4},{'str': b'0.33', 'strlen': 4},{'str': b'0.34', 'strlen': 4},{'str': b'0.35', 'strlen': 4},{'str': b'0.36', 'strlen': 4},{'str': b'0.37', 'strlen': 4},{'str': b'0.38', 'strlen': 4},{'str': b'0.39', 'strlen': 4},{'str': b'1.0\x00', 'strlen': 3},{'str': b'1.1\x00', 'strlen': 3},{'str': b'1.2\x00', 'strlen': 3},{'str': b'1.3\x00', 'strlen': 3},{'str': b'1.4\x00', 'strlen': 3},{'str': b'1.5\x00', 'strlen': 3},{'str': b'1.6\x00', 'strlen': 3},{'str': b'1.7\x00', 'strlen': 3},{'str': b'1.8\x00', 'strlen': 3},{'str': b'1.9\x00', 'strlen': 3},{'str': b'1.10', 'strlen': 4},{'str': b'1.11', 'strlen': 4},{'str': b'1.12', 'strlen': 4},{'str': b'1.13', 'strlen': 4},{'str': b'1.14', 'strlen': 4},{'str': b'1.15', 'strlen': 4},{'str': b'1.16', 'strlen': 4},{'str': b'1.17', 'strlen': 4},{'str': b'1.18', 'strlen': 4},{'str': b'1.19', 'strlen': 4},{'str': b'1.20', 'strlen': 4},{'str': b'1.21', 'strlen': 4},{'str': b'1.22', 'strlen': 4},{'str': b'1.23', 'strlen': 4},{'str': b'1.24', 'strlen': 4},{'str': b'1.25', 'strlen': 4},{'str': b'1.26', 'strlen': 4},{'str': b'1.27', 'strlen': 4},{'str': b'1.28', 'strlen': 4},{'str': b'1.29', 'strlen': 4},{'str': b'1.30', 'strlen': 4},{'str': b'1.31', 'strlen': 4},{'str': b'1.32', 'strlen': 4},{'str': b'1.33', 'strlen': 4},{'str': b'1.34', 'strlen': 4},{'str': b'1.35', 'strlen': 4},{'str': b'1.36', 'strlen': 4},{'str': b'1.37', 'strlen': 4},{'str': b'1.38', 'strlen': 4},{'str': b'1.39', 'strlen': 4},{'str': b'2.0\x00', 'strlen': 3},{'str': b'2.1\x00', 'strlen': 3},{'str': b'2.2\x00', 'strlen': 3},{'str': b'2.3\x00', 'strlen': 3},{'str': b'2.4\x00', 'strlen': 3},{'str': b'2.5\x00', 'strlen': 3},{'str': b'2.6\x00', 'strlen': 3},{'str': b'2.7\x00', 'strlen': 3},{'str': b'2.8\x00', 'strlen': 3},{'str': b'2.9\x00', 'strlen': 3},{'str': b'2.10', 'strlen': 4},{'str': b'2.11', 'strlen': 4},{'str': b'2.12', 'strlen': 4},{'str': b'2.13', 'strlen': 4},{'str': b'2.14', 'strlen': 4},{'str': b'2.15', 'strlen': 4},{'str': b'2.16', 'strlen': 4},{'str': b'2.17', 'strlen': 4},{'str': b'2.18', 'strlen': 4},{'str': b'2.19', 'strlen': 4},{'str': b'2.20', 'strlen': 4},{'str': b'2.21', 'strlen': 4},{'str': b'2.22', 'strlen': 4},{'str': b'2.23', 'strlen': 4},{'str': b'2.24', 'strlen': 4},{'str': b'2.25', 'strlen': 4},{'str': b'2.26', 'strlen': 4},{'str': b'2.27', 'strlen': 4},{'str': b'2.28', 'strlen': 4},{'str': b'2.29', 'strlen': 4},{'str': b'2.30', 'strlen': 4},{'str': b'2.31', 'strlen': 4},{'str': b'2.32', 'strlen': 4},{'str': b'2.33', 'strlen': 4},{'str': b'2.34', 'strlen': 4},{'str': b'2.35', 'strlen': 4},{'str': b'2.36', 'strlen': 4},{'str': b'2.37', 'strlen': 4},{'str': b'2.38', 'strlen': 4},{'str': b'2.39', 'strlen': 4},]

cdef inline int primitive_decode(char *stream, size_t stream_len, uint64_t *result, size_t *result_len):
    cdef size_t i
    cdef uint8_t sid
    cdef int retval = 0
    result_len[0] = 0
    result[0] = 0

    for i in range(stream_len):
        result[result_len[0]] <<= 7
        sid = <uint8_t>stream[i]
        result[result_len[0]] |= sid & 0x7f
        if sid & 0x80 == 0:
            result_len[0] +=1
            result[result_len[0]] = 0

    return retval


cdef inline objectid_decode_str(char *stream, size_t stream_len):
    cdef uint64_t result[122]
    cdef char result_str[MAX_OID_LEN_STR]
    cdef char *result_str_ptr = result_str
    cdef size_t n, ret_len, sid12_enc_len, result_len=0, out_len
    cdef SID12_t tmp_sid

    if <size_t>stream[0] > 127:
        raise Exception("bad objectid")

    tmp_sid = sid12s[<size_t>stream[0]]

    sid12_enc_len = tmp_sid.strlen

    memcpy(result_str_ptr, tmp_sid.str, sid12_enc_len)
    result_str_ptr += sid12_enc_len
    out_len = sid12_enc_len

    primitive_decode((<char *>stream)+1, stream_len-1, result, &result_len)

    for i in range(result_len):
        n = sprintf(result_str_ptr, ".%ld", result[i])
        result_str_ptr += n
        out_len+=n

    return result_str[:out_len]


def objectid_decode(stream):
    cdef char *stream_char = stream
    cdef size_t stream_len = len(stream)
    return objectid_decode_str(stream_char, stream_len)


cdef inline tuple objectid_decode_tuple(char *stream, size_t stream_len):
    cdef size_t result_len=0
    cdef uint64_t result[120]

    objectid_decode_c(stream, stream_len, result, &result_len)
    ret = PyTuple_New(result_len)

    for i in range(result_len):
        val = PyInt_FromLong(result[i])
        Py_INCREF(val)
        PyTuple_SET_ITEM(ret, i, val)
    return ret

cdef inline int objectid_decode_c(char *stream, size_t stream_len, uint64_t *result, size_t *result_len):
    cdef object value
    cdef SID12_ti *sid12_ptr
    cdef size_t i, enc_len=0
    cdef tuple ret
    sid12_ptr = &sid12i[<size_t>stream[0]]
    result[0] = sid12_ptr.SID1
    result[1] = sid12_ptr.SID2
    result_len[0] = 2

    if stream_len > 1:
        primitive_decode(stream+1, stream_len-1, result+2, &enc_len)
        result_len[0] += enc_len

    return 0

@cython.cdivision(True)
cdef inline int primitive_encode(uint64_t *value, char *result_ptr) except -1:
    """
    Primitive encoding
    """
    cdef unsigned int size = 0

    if value[0] < <uint64_t>0x80:  # 7 bit
        result_ptr[0] = value[0]
        size = 1
    elif value[0] < <uint64_t>0x4000:  # 14 bit
        result_ptr[0] = value[0] >> 7 | 0x80
        result_ptr[1] = value[0] & 0x7f
        size = 2
    elif value[0] < <uint64_t>0x200000:  # 21 bit
        result_ptr[0] = value[0] >> 14 & 0x7f | 0x80
        result_ptr[1] = value[0] >> 7 | 0x80
        result_ptr[2] = value[0] & 0x7f
        size = 3
    elif value[0] < <uint64_t>0x10000000:  # 28 bit
        result_ptr[0] = value[0] >> 21 & 0x7f | 0x80
        result_ptr[1] = value[0] >> 14 & 0x7f | 0x80
        result_ptr[2] = value[0] >> 7 | 0x80
        result_ptr[3] = value[0] & 0x7f
        size = 4
    elif value[0] < <uint64_t>0x800000000:  # 35 bit
        result_ptr[0] = value[0] >> 28 & 0x7f | 0x80
        result_ptr[1] = value[0] >> 21 & 0x7f | 0x80
        result_ptr[2] = value[0] >> 14 & 0x7f | 0x80
        result_ptr[3] = value[0] >> 7 | 0x80
        result_ptr[4] = value[0] & 0x7f
        size = 5
    elif value[0] < <uint64_t>0x40000000000:  # 42 bit
        result_ptr[0] = value[0] >> 35 & 0x7f | 0x80
        result_ptr[1] = value[0] >> 28 & 0x7f | 0x80
        result_ptr[2] = value[0] >> 21 & 0x7f | 0x80
        result_ptr[3] = value[0] >> 14 & 0x7f | 0x80
        result_ptr[4] = value[0] >> 7 | 0x80
        result_ptr[5] = value[0] & 0x7f
        size = 6
    elif value[0] < <uint64_t>0x2000000000000:  # 49 bit
        result_ptr[0] = value[0] >> 42 & 0x7f | 0x80
        result_ptr[1] = value[0] >> 35 & 0x7f | 0x80
        result_ptr[2] = value[0] >> 28 & 0x7f | 0x80
        result_ptr[3] = value[0] >> 21 & 0x7f | 0x80
        result_ptr[4] = value[0] >> 14 & 0x7f | 0x80
        result_ptr[5] = value[0] >> 7 | 0x80
        result_ptr[6] = value[0] & 0x7f
        size = 7
    elif value[0] < <uint64_t>0x100000000000000:  # 56 bit
        result_ptr[0] = value[0] >> 49 & 0x7f | 0x80
        result_ptr[1] = value[0] >> 42 & 0x7f | 0x80
        result_ptr[2] = value[0] >> 35 & 0x7f | 0x80
        result_ptr[3] = value[0] >> 28 & 0x7f | 0x80
        result_ptr[4] = value[0] >> 21 & 0x7f | 0x80
        result_ptr[5] = value[0] >> 14 & 0x7f | 0x80
        result_ptr[6] = value[0] >> 7 | 0x80
        result_ptr[7] = value[0] & 0x7f
        size = 7
    else:
        # TODO: implement iterative calculation
        return -1

    return size


@cython.cdivision(True)
cdef inline int objectid_encode_array(uint64_t *subids, uint32_t subids_len,
                                      char *result, size_t *object_len):
    cdef uint32_t clen
    cdef uint64_t subid
    cdef size_t i
    cdef int retval = 0
    cdef size_t sid_len = 0
    cdef char *result_ptr

    if subids[0] == 2 and subids[1] > 39:
        return -3  # long SID1 is not supported

    if subids[0] > 2:
        return -1  # wrong SID1

    if subids[1] > 39:
        return -2  # wrong SID2

    result[0] = subids[0]*40 + subids[1]
    object_len[0] = 1
    result_ptr = result+1

    for i in range(2, subids_len):
        subid = subids[i]
        sid_len = primitive_encode(&subid, result_ptr)
        object_len[0] += sid_len
        result_ptr = result_ptr+sid_len
    return retval

def objectid_encode(oid):
    """
    encode an ObjectID into stream
    X.690, chapter 8.19
    :param oid: OID
    :type oid: str
    :returns: stream
    :rtype: bytearray
    """
    cdef unsigned int number
    cdef uint64_t idlist[128]
    cdef list subidlist
    cdef size_t pos = 0
    cdef size_t object_len = 0
    cdef char result[256]
    cdef str subid
    for subid in oid.strip('.').split('.'):
        idlist[pos] = int(subid)
        pos += 1
    ret = objectid_encode_array(idlist, pos, result, &object_len)

    if ret != 0:
        if ret == -1:
            raise Exception("wrong SID1")
        elif ret == -2:
            raise Exception("wrong SID2")
        elif ret == -3:
            raise Exception("long SID1 is not supported")

    return <bytes>result[:object_len]

cdef inline object c_octetstring_decode(char *data, size_t data_len, bint auto_str=1):
    cdef object ret
    if auto_str:
        for i in range(data_len):
            if <uint8_t>data[i] > 127:
                return <bytes> data[:data_len]
        return data[:data_len]
    else:
        return <bytes> data[:data_len]

def octetstring_decode(bytes stream not None, int auto_str=1):
    return c_octetstring_decode(stream, len(stream), auto_str)


def octetstring_encode(string):
    """
    encode an octetstring into string

    :param string: string
    :type string: string
    :returns: string
    :rtype: bytes
    """
    return bytes(string.encode('ascii'))


cdef inline size_t ber_encode_integer_size(const int64_t value):
    cdef size_t len = 1
    cdef int64_t tmp = value
    cdef bint is_most_sig_set = tmp & 0x80
    tmp >>= 8
    # how many bytes are used in value
    while tmp != 0:
        len += 1
        is_most_sig_set = tmp & 0x80
        tmp >>= 8
    # in unsigned number most significant bit must be not set
    if is_most_sig_set:
        return len + 1
    else:
        return len

def integer_encode(const uint64_t value):
    # little -> big
    cdef size_t slen, i
    cdef char[8] res
    slen = ber_encode_integer_size(value)

    # copy the bytes from value to data backwards
    for i in range(0, slen):
        res[slen-i-1] = (<char *> &value)[i]
    return <bytes> res[:slen]

def integer_decode(bytes stream not None):
    """
    Decode input stream into a integer

    :param stream: encoded integer
    :type stream: bytes
    :returns: decoded integer
    :rtype: int
    """
    cdef uint64_t value = 0
    cdef uint8_t i
    cdef size_t stream_len = len(stream)
    cdef char *stream_char = stream
    for i in range(stream_len):
        value <<= 8
        value |= <uint8_t>stream_char[i]
    return value

def integer_decode(bytes stream not None):
    """
    Decode input stream into a integer

    :param stream: encoded integer
    :type stream: bytes
    :returns: decoded integer
    :rtype: int
    """
    cdef uint64_t value = 0
    cdef uint8_t i
    cdef size_t stream_len = len(stream)
    cdef char *stream_char = stream
    return integer_decode_c(stream_char, &stream_len)

cdef inline uint64_t integer_decode_c(char *stream, size_t *stream_len):
    cdef uint64_t value = 0
    cdef uint8_t i
    for i in range(stream_len[0]):
        value <<= 8
        value |= <uint8_t>stream[i]
    return value

def sequence_decode(bytes stream not None) -> list:
    cdef char * stream_char = stream
    cdef size_t stream_len = len(stream)
    cdef list ret
    ret = sequence_decode_c(stream_char, stream_len)
    return ret

cdef list sequence_decode_c(char *stream, size_t stream_len):
    """
    Decode input stream into as sequence

    :param stream: sequence
    :type stream: bytes
    :returns: decoded sequence
    :rtype: list
    """
    cdef uint64_t tag=0, tmp_int_val
    cdef size_t encode_length, length, offset=0
    cdef object str_val
    cdef char * stream_char = stream
    cdef list objects=[], tmp_list_val
    cdef tuple tmp_tuple_val
    cdef str tmp_objectid

    while offset<stream_len:
        tag_decode_c(stream_char, &tag, &encode_length)
        stream_char += encode_length
        offset += encode_length

        length_decode_c(stream_char, &length, &encode_length)
        stream_char+=encode_length
        offset += encode_length

        if tag in [0x02, 0x40, 0x41, 0x42, 0x46, 0x43]:
            tmp_int_val = integer_decode_c(stream_char, &length)
            objects.append(tmp_int_val)
        elif tag == 0x06:
            tmp_objectid = objectid_decode_str(stream_char, length)
            objects.append(tmp_objectid)
        elif tag in [0x80, 0x81, 0x82, 0x05]:
            objects.append(None)
        elif tag in [0x30, 0xa2, 0xa5]:
            tmp_list_val = sequence_decode_c(stream_char, length)
            objects.append(tmp_list_val)
        elif tag in [0x04, 0x40]:
            str_val = c_octetstring_decode(stream_char, length, 1)
            objects.append(str_val)
        else:
            raise NotImplementedError(tag)

        offset += length
        stream_char += length
    return objects


cdef int length_decode_c(char *stream, size_t *length, size_t *enc_len):
    """
    X.690 8,1,3
    """
    length[0] = <uint8_t>stream[0]
    enc_len[0] = 1

    if length[0] & 0x80 == 0x80:  # 8.1.3.5
        enc_len[0] = length[0] & 0x7f
        length[0] = integer_decode_c(stream+1, enc_len)
        enc_len[0] += 1

    return 0


def length_decode(bytes data):
    cdef size_t encode_length, length
    length_decode_c(data, &length, &encode_length)
    return length, encode_length


def length_encode(length):
    """
    Function takes the length of the contents and
    produces the encoding for that length.  Section 6.3 of
    ITU-T-X.209

    :param length: length
    :type length: int
    :returns: encoded length
    :rtype: bytes
    """
    if length in length_cache:
        return length_cache[length]

    if length < 127:
        result = bytes([length & 0xff])
    else:
        # Long form - Octet one is the number of octets used to
        # encode the length It has bit 8 set to 1 and the
        # remaining 7 bits are used to encode the number of octets
        # used to encode the length Each subsequent octet uses all
        # 8 bits to encode the length

        resultlist = bytearray()
        numOctets = 0
        while length > 0:
            resultlist.insert(0, length & 0xff)
            length >>= 8
            numOctets += 1
        # Add a 1 to the front of the octet
        numOctets |= 0x80
        resultlist.insert(0, numOctets & 0xff)
        result = resultlist
    return result

cdef inline int tag_decode_c(char *stream, uint64_t *tag, size_t *enc_len) except -1:
    """
    X.690 8.1.2

    Decode a BER tag field, returning the tag and the remainder
    of the stream
    """

    tag[0] = <uint8_t>stream[0]  # low-tag-number form
    enc_len[0] = 1
    if tag[0] & 0x1F == 0x1F:  # high-tag-number form
        return -1

    return 0

def tag_decode(bytes stream not None):
    cdef uint64_t tag=0
    cdef size_t encode_length
    tag_decode_c(stream, &tag, &encode_length)
    return tag, encode_length


def tag_encode(asn_tag_class, asn_tag_format, asn_tag_number):
    """
    Returns encoded identifier octets for
    this object.  Section 6.3 of ITU-T-X.209

    :param asn_tag_class: asn tag class
    :type asn_tag_class: int
    :param asn_tag_format: asn tag format
    :type asn_tag_format: int
    :param asn_tag_number: asn tag number
    :type asn_tag_number: int
    :returns: tag
    :rtype: bytes
    """
    if asn_tag_number < 0x1F:
        result = bytes([asn_tag_class | asn_tag_format | asn_tag_number])
    else:
        # # Encode each number of the asnTagNumber from 31 upwards
        # # as a sequence of 7-bit numbers with bit 8 set to 1 for
        # # all but the last octet. Bit 8 set to 0 signifies the
        # # last octet of the Identifier octets
        # encode the first octet
        resultlist = bytearray()
        resultlist.append(asn_tag_class | asn_tag_format | 0x1F)

        # encode each subsequent octet
        integer = asn_tag_number
        while integer != -1:
            resultlist.append(integer & 0xFF)
            integer >>= 8
        result = resultlist
    return result


# TODO: implement more encoders
def value_encode(value=None, value_type='Null'):
    """
    Encoded value by ASN.1
    """
    if value_type == 'Null':
        if value is not None:
            raise Exception('value must be None for Null type!')
        return b''
    elif value_type == "Integer":
        return integer_encode(value)
    elif value_type == "OctetString":
        return value.encode()
    else:
        raise NotImplementedError('not implement coder for %s' % type(value))


def encode_varbind(oid, value_type='Null', value=None):
    if value is None:
        value_type = 'Null'
    obj_id = objectid_encode(oid)
    obj_id_id = tag_encode(asnTagClasses['UNIVERSAL'], asnTagFormats['PRIMITIVE'], ASN_TYPES['ObjectID'])
    obj_id_len = length_encode(len(obj_id))

    obj_value = value_encode(value, value_type)
    obj_value_id = tag_encode(asnTagClasses['UNIVERSAL'], asnTagFormats['PRIMITIVE'], ASN_TYPES[value_type])
    obj_value_len = length_encode(len(obj_value))

    varbinds_obj = obj_id_id + obj_id_len + obj_id + obj_value_id + obj_value_len + obj_value

    seq_tag = tag_encode(asnTagClasses['UNIVERSAL'], asnTagFormats['CONSTRUCTED'], ASN_TYPES['Sequence'])
    varbind_enc = seq_tag + length_encode(len(varbinds_obj)) + varbinds_obj
    return varbind_enc


def varbinds_encode(varbinds):
    res = bytearray()
    for varbind in varbinds:
        if len(varbind) == 3:
            oid, value_type, value = varbind
        elif len(varbind) == 2:
            oid, value_type = varbind
            value = None
        else:
            oid = varbind
            value = None
            value_type = "Null"
        res += encode_varbind(oid, value_type, value)
    return res


def varbinds_encode_tlv(varbinds):
    varbinds_data = varbinds_encode(varbinds)
    varbinds_id = tag_encode(asnTagClasses['UNIVERSAL'], asnTagFormats['CONSTRUCTED'], ASN_TYPES['Sequence'])
    varbinds_len = length_encode(len(varbinds_data))
    return varbinds_id + varbinds_len + varbinds_data


def msg_encode(req_id, community, varbinds, msg_type="GetBulk", max_repetitions=10, non_repeaters=0):
    """
    Build SNMP-message

    :param req_id: request identifier
    :type req_id: int
    :param community: snmp community
    :type community: string
    :param varbinds: list of oid to encode or bytes if encoded
    :type varbinds: tuple
    :param msg_type: index of ASN_SNMP_MSG_TYPES
    :type msg_type: str
    :param max_repetitions: max repetitions
    :type community: int
    :param non_repeaters: non repeaters
    :type varbinds: int
    :returns: encoded message
    :rtype: bytes
    """
    if isinstance(varbinds, (list, tuple)):
        varbinds_tlv = varbinds_encode_tlv(varbinds)
    else:
        varbinds_tlv = varbinds

    requestID_id = tag_encode(asnTagClasses['UNIVERSAL'], asnTagFormats['PRIMITIVE'], ASN_TYPES['Integer'])
    requestID = integer_encode(req_id)
    requestID_len = length_encode(len(requestID))



    if msg_type == "GetBulk":
        nonRepeaters = integer_encode(non_repeaters)
        nonRepeaters_id = tag_encode(asnTagClasses['UNIVERSAL'], asnTagFormats['PRIMITIVE'], ASN_TYPES['Integer'])
        nonRepeaters_len = length_encode(len(nonRepeaters))

        maxRepetitions = integer_encode(max_repetitions)
        maxRepetitions_id = tag_encode(asnTagClasses['UNIVERSAL'], asnTagFormats['PRIMITIVE'], ASN_TYPES['Integer'])
        maxRepetitions_len = length_encode(len(maxRepetitions))
        pdu = requestID_id + requestID_len + requestID + \
                nonRepeaters_id + nonRepeaters_len + nonRepeaters + \
                maxRepetitions_id + maxRepetitions_len + maxRepetitions + \
                varbinds_tlv
    else:
        error_status = integer_encode(0)
        error_status_id = tag_encode(asnTagClasses['UNIVERSAL'], asnTagFormats['PRIMITIVE'], ASN_TYPES['Integer'])
        error_status_len = length_encode(len(error_status))
        error_index = integer_encode(0)
        error_index_id = tag_encode(asnTagClasses['UNIVERSAL'], asnTagFormats['PRIMITIVE'], ASN_TYPES['Integer'])
        error_index_len = length_encode(len(error_index))
        pdu = requestID_id + requestID_len + requestID + \
                error_status_id + error_status_len + error_status + \
                error_index_id + error_index_len + error_index + \
                varbinds_tlv

    pdu_id = tag_encode(asnTagClasses['CONTEXT'], asnTagFormats['CONSTRUCTED'], ASN_SNMP_MSG_TYPES[msg_type])
    pdu_len = length_encode(len(pdu))

    community = octetstring_encode(community)
    community_id = tag_encode(asnTagClasses['UNIVERSAL'], asnTagFormats['PRIMITIVE'], ASN_TYPES['OctetString'])
    community_len = length_encode(len(community))

    version = integer_encode(1)
    version_id = tag_encode(asnTagClasses['UNIVERSAL'], asnTagFormats['PRIMITIVE'], ASN_TYPES['Integer'])
    version_len = length_encode(len(version))

    snmp_message_seq_id = tag_encode(asnTagClasses['UNIVERSAL'], asnTagFormats['CONSTRUCTED'], ASN_TYPES['Sequence'])
    snmp_message_len = length_encode(len(version_id + version_len + version + \
                   community_id + community_len + community + \
                   pdu_id + pdu_len + pdu))

    snmp_message = snmp_message_seq_id + snmp_message_len + version_id + version_len + version + \
                   community_id + community_len + community + \
                   pdu_id + pdu_len + pdu

    return snmp_message


def msg_decode(stream):
    cdef uint64_t tag=0
    cdef size_t encode_length, length
    cdef char* stream_char = stream
    cdef char* stream_ptr = stream_char
    cdef size_t stream_len = len(stream)
    cdef list data

    tag_decode_c(stream_ptr, &tag, &encode_length)
    stream_ptr += encode_length
    length_decode_c(stream_ptr, &length, &encode_length)
    stream_ptr += encode_length
    snmp_ver, community, data = sequence_decode_c(stream_ptr, length)
    req_id, error_status, error_index, varbinds = data
    return req_id, error_status, error_index, varbinds


def parse_varbind(list var_bind_list not None, tuple orig_main_oids not None, tuple oids_to_poll not None):
    cdef str oid, main_oid, index_part
    cdef list result = [], item
    cdef list next_oids = list()
    cdef list orig_main_oids_doted = list()
    cdef list orig_main_oids_len = list()
    cdef object value
    rest_oids_positions = [x for x in range(len(oids_to_poll)) if oids_to_poll[x]]
    main_oids_len = len(rest_oids_positions)
    main_oids_positions = cycle(rest_oids_positions)
    var_bind_list_len = len(var_bind_list)

    for i in orig_main_oids:
        orig_main_oids_doted.append(i + ".")
        orig_main_oids_len.append(len(i))

    skip_column = {}
    # if some oid in requested oids is not supported, column with it is index will
    # be filled with another oid. need to skip
    last_seen_index = {}

    for var_bind_pos in range(var_bind_list_len):
        item = var_bind_list[var_bind_pos]
        # if item is None:
        #     raise VarBindUnpackException("bad value in %s at %s" % (var_bind_list, var_bind_pos))
        try:
            oid, value = item
        except (ValueError, TypeError) as e:
            raise VarBindUnpackException("Exception='%s' item=%s" % (e, item))
        if not isinstance(oid, str):
            raise VarBindContentException("expected oid in str. got %r" % oid)
        main_oids_pos = next(main_oids_positions)
        if value is None:
            skip_column[main_oids_pos] = True
        if main_oids_pos in skip_column:
            continue
        main_oid = orig_main_oids_doted[main_oids_pos]
        if oid.startswith(main_oid):
            index_part = oid[orig_main_oids_len[main_oids_pos]+1:]
            last_seen_index[main_oids_pos] = index_part
            result.append([orig_main_oids[main_oids_pos], index_part, value])
        else:
            skip_column[main_oids_pos] = True
            if len(skip_column) == var_bind_list_len:
                break
    if len(skip_column) < main_oids_len:
        if len(skip_column):
            next_oids = [None,] * len(orig_main_oids)
            for pos in rest_oids_positions:
                if pos in skip_column:
                    continue
                next_oids[pos] = "%s.%s" % (orig_main_oids[pos], last_seen_index[pos])
        else:
            next_oids = [
                "%s.%s" % (orig_main_oids[p], last_seen_index[p]) for p in rest_oids_positions]

    return result, tuple(next_oids)
