# This test exercises a previous bug in binpac flowbuffer frame length
# boundary checks:

# Incremental flowbuffer parsing sought to first parse the "minimum header
# length" required to get the full frame length, possibly from a record
# field, but generating the logic to parse that field could greedily
# bundle in additional boundary-checks for all subsequent fields of
# known-size.
#
# E.g. for flowunit parsing of this:
#
#     type HDR = record {
#         version:    uint8;
#         reserved:   uint8;
#         len:        uint16;
#     } &byteorder=bigendian;
#
#     type FOO_PDU(is_orig: bool) = record {
#         hdr:        HDR;
#         plen:       uint8;
#         ptype:      uint8;
#         something:  bytestring &restofdata;
#     } &byteorder=bigendian, &length=hdr.len;

# The flowbuffer was correctly seeking to buffer 4 bytes and parse the
# "hdr.len" field, but the generated parsing logic for "hdr.len" included
# a boundary check all the way up to include "plen" and "ptype".

# This causes out-of-bounds exceptions to be thrown for inputs that should
# actually be possible to incrementally parse via flowbuffer.

# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Foo FOO
# @TEST-EXEC: cp -r %DIR/binpac-flowbuffer-frame-length-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -r $TRACES/mmsX.pcap %INPUT >output

event Foo::foo_message(c: connection, is_orig: bool, len: count, plen: count, ptype: count)
	{
	print "foo_message", len, plen, ptype;
	}
