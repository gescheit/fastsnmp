# cython: embedsignature=True
# cython: language_level=3
# adds doc-strings for sphinx
# -*- coding: utf-8 -*-
# based on https://pypi.python.org/pypi/libsnmp/
import binascii
from itertools import cycle
DEBUG = True


class SNMPException(Exception):
    pass


class VarBindUnpackException(SNMPException):
    pass

# X.690
# http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf

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
id_cache = {}
tag_cache = {}
integer_decode_cache = {b'\x00': 0, b'\x01': 1}
integer_encode_cache = {0: b'\x00', 1: b'\x01'}
sequence_cache = {}

length_cache = {}
length_cache[0] = b'\x00'
length_cache[1] = b'\x01'


def pdu_response_decode(stream):
    return sequence_decode(stream)


def objectid_decode(stream):
    """Decode a stream into an ObjectID.

    :param stream: stream with OID
    :type stream: bytes
    :returns: OID
    :rtype: str
    """
    if not stream:
        raise ValueError('stream of zero length in')
    if stream in id_cache:
        return id_cache[stream]
    value = list()
    # #
    # # Do the funky decode of the first octet
    # #

    if stream[0] < 128:
        value.append(stream[0] // 40)
        value.append(stream[0] % 40)
    else:
        # # I haven't bothered putting in the convoluted logic here
        # # because the highest likely assignment for the first
        # # octet is 83 according to Annex B of X.208 Those X.209
        # # does give as an example 2.100.3, which is kinda stupid.
        # # Actually, a lot of the space-saving encodings, like
        # # this first octet, are a real PITA later on.  So yeah,
        # # stuff it, we'll just raise an exception.
        raise ValueError('stream of zero length in objectid_decode()')
    # #
    # # Decode the rest of the octets
    # #
    n = 1
    bytes_len = len(stream)
    while n < bytes_len:
        subid = stream[n]
        n += 1
        # #
        # # If bit 8 is not set, this is the last octet of this subid
        # # If bit 8 is set, the subid spans this octet and the ones
        # # afterwards, up until bit 8 isn't set.
        # #
        if subid & 0x80 == 0x80:
            val = subid & 0x7f
            while (subid & 0x80) == 0x80:
                subid = stream[n]
                n += 1
                val = (val << 7) | (subid & 0x7f)
            value.append(val)
        else:
            value.append(subid)
    value = ".".join(map(str, value))
    id_cache[stream] = value
    return value


def objectid_encode(oid):
    """
    encode an ObjectID into stream

    :param oid: OID
    :type oid: str
    :returns: stream
    :rtype: bytearray
    """
    value = oid.strip('.')
    subidlist = value.split('.')
    value = []

    for subid in subidlist:
        number = int(subid)
        if number < 0 or number > 0x7FFFFFFF:
            raise ValueError("SubID out of range")
        value.append(number)

    result = bytearray()
    idlist = value[:]

    # Do the bit with the first 2 subids
    # section 22.4 of X.209
    idlist.reverse()
    subid1 = (idlist.pop() * 40) + idlist.pop()
    idlist.reverse()
    idlist.insert(0, subid1)

    for subid in idlist:
        if subid < 128:
            result.append(subid & 0x7f)
        else:
            position = len(result)
            result.append(subid & 0x7f)

            subid = subid >> 7
            while subid > 0:
                result.insert(position, 0x80 | (subid & 0x7f))
                subid = subid >> 7

    return result


def octetstring_decode(stream):
    """
    decode an octetstring into string

    :param stream: stream
    :type stream: bytes
    :returns: string
    :rtype: string
    """
    try:
        return stream.decode()
    except UnicodeDecodeError:
        return binascii.hexlify(stream)


def octetstring_encode(string):
    """
    encode an octetstring into string

    :param string: string
    :type string: string
    :returns: string
    :rtype: bytes
    """
    return bytes(string.encode('ascii'))


def integer_encode(integer):
    """
    encode an integer

    :param integer: target integer
    :type integer: int
    :returns: integer
    :rtype: bytes
    """
    if integer in integer_encode_cache:
        return integer_encode_cache[integer]
    elif integer > 0:
        return integer.to_bytes(integer.bit_length() // 8 + 1, byteorder='big', signed=True)


def integer_decode(stream):
    """
    Decode input stream into a integer

    :param stream: encoded integer
    :type stream: bytes
    :returns: decoded integer
    :rtype: int
    """
    if stream in integer_encode_cache:
        return integer_decode_cache[stream]
    else:
        return int.from_bytes(stream, byteorder='big', signed=True)


def sequence_decode(stream):
    """
    Decode input stream into as sequence

    :param stream: sequence
    :type stream: bytes
    :returns: decoded sequence
    :rtype: list
    """
    objects = []
    while stream:
        (tag, stream) = tag_decode(stream)
        (length, stream) = length_decode(stream)
        objectData = stream[:length]
        stream = stream[length:]
        parsed_objectData = tagDecodeDict[tag](objectData)
        objects.append(parsed_objectData)
    return objects

tagDecodeDict = {
    0x02: integer_decode,
    0x04: octetstring_decode,
    0x05: lambda x: b'',
    0x06: objectid_decode,
    0x30: sequence_decode,

    # Application types
    0x40: octetstring_decode,  # IPAddress,
    0x41: integer_decode,  # Counter
    0x42: integer_decode,  # Gauge
    0x46: integer_decode,  # Counter64
    0x43: integer_decode,  # TimeTicks,

    0xa2: pdu_response_decode,
    0x80: lambda x: None,  # NoSuchObject_TAG
    0x81: lambda x: None,  # NoSuchInstance_TAG
    0x82: lambda x: None,  # EndOfMibView_TAG
}


def length_decode(stream):
    """
    Decode a BER length field, returing the length and the
    remainder of the stream

    :param stream: sequence
    :type stream: bytes
    :returns: (length, remaining stream)
    :rtype: tuple
    """
    length = stream[0]
    n = 1
    if length & 0x80:
        # Multi-Octet length encoding.  The first octet
        # represents the run-length (the number of octets used to
        # build the length)
        run = length & 0x7F
        length = 0
        for i in range(run):
            length = (length << 8) | stream[n]
            n += 1
    return length, stream[n:]


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


def tag_decode(stream):
    """
    Decode a BER tag field, returning the tag and the remainder
    of the stream

    :param stream: stream
    :type stream: bytes
    :returns: (tag, remaining stream)
    :rtype: tuple
    """
    tag = stream[0]
    n = 1
    if tag & 0x1F == 0x1F:

        # # A large tag is encoded using concatenated 7-bit values
        # # over the following octets, ignoring the initial 5 bits
        # # in the first octet.  The 8th bit represents a
        # # follow-on.

        tag = 0
        while 1:
            byte = ord(stream[n])
            tag = (tag << 7) | (byte & 0x7F)
            n += 1
            if not byte & 0x80:
                break

    return tag, stream[n:]


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


def msg_encode(req_id, community, varbinds, msg_type="GetBulk", max_repetitions=10, non_repeaters=0):
    """
    Build SNMP-message

    :param req_id: request identifier
    :type req_id: int
    :param community: snmp community
    :type community: string
    :param varbinds: list of oid to encode
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
    varbinds_data = varbinds_encode(varbinds)
    varbinds_id = tag_encode(asnTagClasses['UNIVERSAL'], asnTagFormats['CONSTRUCTED'], ASN_TYPES['Sequence'])
    varbinds_len = length_encode(len(varbinds_data))

    requestID_id = tag_encode(asnTagClasses['UNIVERSAL'], asnTagFormats['PRIMITIVE'], ASN_TYPES['Integer'])
    requestID = integer_encode(req_id)
    requestID_len = length_encode(len(requestID))

    nonRepeaters = integer_encode(non_repeaters)
    nonRepeaters_id = tag_encode(asnTagClasses['UNIVERSAL'], asnTagFormats['PRIMITIVE'], ASN_TYPES['Integer'])
    nonRepeaters_len = length_encode(len(nonRepeaters))

    maxRepetitions = integer_encode(max_repetitions)
    maxRepetitions_id = tag_encode(asnTagClasses['UNIVERSAL'], asnTagFormats['PRIMITIVE'], ASN_TYPES['Integer'])
    maxRepetitions_len = length_encode(len(maxRepetitions))

    pdu = requestID_id + requestID_len + requestID + \
            nonRepeaters_id + nonRepeaters_len + nonRepeaters + \
            maxRepetitions_id + maxRepetitions_len + maxRepetitions + \
            varbinds_id + varbinds_len + varbinds_data

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
    (tag, stream) = tag_decode(stream)
    (length, stream) = length_decode(stream)
    objectData = stream[:length]
    stream = stream[length:]
    snmp_ver, community, data = tagDecodeDict[tag](objectData)
    req_id, error_status, error_index, varbinds = data
    return req_id, error_status, error_index, varbinds


def parse_varbind(var_bind_list, orig_main_oids, oids_to_poll):
    result = []
    next_oids = None
    rest_oids_positions = [x for x in range(len(oids_to_poll)) if oids_to_poll[x]]
    main_oids_len = len(rest_oids_positions)
    main_oids_positions = cycle(rest_oids_positions)
    var_bind_list_len = len(var_bind_list)

    skip_column = {}
    # if some oid in requested oids is not supported, column with it is index will
    # be filled with another oid. need to skip
    last_seen_index = {}

    for var_bind_pos in range(var_bind_list_len):
        item = var_bind_list[var_bind_pos]
        try:
            oid, value = item
        except ValueError as e:
            raise VarBindUnpackException("ValueError='%s' item=%s" % (e, item))
        # oids in received var_bind_list in round-robin order respectively query
        main_oids_pos = next(main_oids_positions)
        if value is None:
            skip_column[main_oids_pos] = True
        if main_oids_pos in skip_column:
            continue
        main_oid = orig_main_oids[main_oids_pos]
        if oid.startswith(main_oid + '.'):
            index_part = oid[len(main_oid) + 1:]
            last_seen_index[main_oids_pos] = index_part
            result.append((main_oid, index_part, value))
        else:
            skip_column[main_oids_pos] = True
            if len(skip_column) == var_bind_list_len:
                break
    if len(skip_column) < main_oids_len:
        if len(skip_column):
            next_oids = [None for _ in range(len(orig_main_oids))]
            for pos in rest_oids_positions:
                if pos in skip_column:
                    continue
                next_oids[pos] = "%s.%s" % (orig_main_oids[pos], last_seen_index[pos])
            next_oids = tuple(oids_to_poll)
        else:
            next_oids = tuple(
                "%s.%s" % (orig_main_oids[p], last_seen_index[p]) for p in rest_oids_positions)

    return result, next_oids
