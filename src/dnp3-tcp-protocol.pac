# $Id:$
#
# This template code contributed by Kristin Stephens.

type Sample_Message = record {
	before_length: uint8[16];
	length: uint16;
	after_length: bytestring &restofdata;
} &byteorder = bigendian &length=length &let {
	deliver: bool = $context.flow.deliver_message(length);
};
