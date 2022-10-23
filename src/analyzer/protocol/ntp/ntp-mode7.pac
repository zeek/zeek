# This is a mode7 message as described below.
# The documentation below is taken from the NTP official project (www.ntp.org),
# code v. ntp-4.2.8p13, in include/ntp_request.h.
#
# A mode 7 packet is used exchanging data between an NTP server
# and a client for purposes other than time synchronization, e.g.
# monitoring, statistics gathering and configuration.  A mode 7
# packet has the following format:
#
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |R|M| VN  | Mode|A|  Sequence   | Implementation|   Req Code    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  Err  | Number of data items  |  MBZ  |   Size of data item   |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                                                               |
#   |            Data (Minimum 0 octets, maximum 500 octets)        |
#   |                                                               |
#                                 [...]
#   |                                                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |               Encryption Keyid (when A bit set)               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                                                               |
#   |          Message Authentication Code (when A bit set)         |
#   |                                                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# where the fields are (note that the client sends requests, the server
# responses):
#
# Response Bit:  This packet is a response (if clear, packet is a request).
#
# More Bit: Set for all packets but the last in a response which
#           requires more than one packet.
#
# Version Number: 2 for current version
#
# Mode: Always 7
#
# Authenticated bit: If set, this packet is authenticated.
#
# Sequence number: For a multipacket response, contains the sequence
#        number of this packet.  0 is the first in the sequence,
#        127 (or less) is the last.  The More Bit must be set in
#        all packets but the last.
#
# Implementation number: The number of the implementation this request code
#        is defined by.  An implementation number of zero is used
#        for request codes/data formats which all implementations
#        agree on.  Implementation number 255 is reserved (for
#        extensions, in case we run out).
#
# Request code: An implementation-specific code which specifies the
#        operation to be (which has been) performed and/or the
#        format and semantics of the data included in the packet.
#
# Err: Must be 0 for a request.  For a response, holds an error
#        code relating to the request.  If nonzero, the operation
#        requested wasn't performed.
#
#        0 - no error
#        1 - incompatible implementation number
#        2 - unimplemented request code
#        3 - format error (wrong data items, data size, packet size etc.)
#        4 - no data available (e.g. request for details on unknown peer)
#        5-6 I don't know
#        7 - authentication failure (i.e. permission denied)
#
# Number of data items: number of data items in packet.  0 to 500
#
# MBZ: A reserved data field, must be zero in requests and responses.
#
# Size of data item: size of each data item in packet.  0 to 500
#
# Data: Variable sized area containing request/response data.  For
#        requests and responses the size in octets must be greater
#        than or equal to the product of the number of data items
#        and the size of a data item.  For requests the data area
#        must be exactly 40 octets in length.  For responses the
#        data area may be any length between 0 and 500 octets
#        inclusive.
#
# Message Authentication Code: Same as NTP spec, in definition and function.
#        May optionally be included in requests which require
#        authentication, is never included in responses.
#
# The version number, mode and keyid have the same function and are
# in the same location as a standard NTP packet.  The request packet
# is the same size as a standard NTP packet to ease receive buffer
# management, and to allow the same encryption procedure to be used
# both on mode 7 and standard NTP packets.  The mac is included when
# it is required that a request be authenticated, the keyid should be
# zero in requests in which the mac is not included.
#
# The data format depends on the implementation number/request code pair
# and whether the packet is a request or a response.  The only requirement
# is that data items start in the octet immediately following the size
# word and that data items be concatenated without padding between (i.e.
# if the data area is larger than data_items*size, all padding is at
# the end).  Padding is ignored, other than for encryption purposes.
# Implementations using encryption might want to include a time stamp
# or other data in the request packet padding.  The key used for requests
# is implementation defined, but key 15 is suggested as a default.

type NTP_mode7_msg = record {
	second_byte       : uint8;
	implementation    : uint8;
	request_code      : uint8;
	err_and_data_len  : uint16;
	data              : bytestring &length=data_len;
	have_mac          : case(auth_bit) of {
		true  -> mac: NTP_MAC;
		false -> nil: empty;
	};
} &let {
	auth_bit  : bool   = (second_byte & 0x80) > 0;
	sequence  : uint8  = (second_byte & 0x7F);
	error_code: uint8  = (err_and_data_len & 0xF000) >> 12;
	data_len  : uint16 = (err_and_data_len & 0x0FFF);
} &byteorder=bigendian &exportsourcedata;

