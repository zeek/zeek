##! MQTT control packet parser, contributed by Supriya Sudharani Kumaraswamy

enum MQTT_msg_type {
	MQTT_RESERVED    = 0,
	MQTT_CONNECT     = 1,
	MQTT_CONNACK     = 2,
	MQTT_PUBLISH     = 3,
	MQTT_PUBACK      = 4,
	MQTT_PUBREC      = 5,
	MQTT_PUBREL      = 6,
	MQTT_PUBCOMP     = 7,
	MQTT_SUBSCRIBE   = 8,
	MQTT_SUBACK      = 9,
	MQTT_UNSUBSCRIBE = 10,
	MQTT_UNSUBACK    = 11,
	MQTT_PINGREQ     = 12,
	MQTT_PINGRESP    = 13,
	MQTT_DISCONNECT  = 14,
};

type MQTT_string = record {
	len : uint16;
	str : bytestring &length=len;
};

# These values are all defined in the commands/*.pac files...
type Command(pdu: MQTT_PDU, msg_type: uint8) = case msg_type of {
	default -> unknown : empty;
};

type MQTT_PDU(is_orig: bool) = record {
	fixed_header     : uint8;
	remaining_length : uint8[] &until(($element & 0x80) != 0x80);
	command          : Command(this, msg_type) &length=real_length;
} &let {
	msg_type : uint8 = (fixed_header >> 4);
	real_length = $context.connection.calc_header_length(remaining_length);
} &byteorder=bigendian;

refine connection MQTT_Conn += {
	# This implementation is ripped straight from the spec.
	function calc_header_length(vals: uint8[]): uint32
		%{
		int multiplier = 1;
		uint32_t value = 0;

		if ( vals->size() > 4 )
			{
			this->zeek_analyzer()->AnalyzerViolation("malformed MQTT 'remaining length': too many bytes");
			return 0;
			}

		for ( auto encoded_byte: *vals )
			{
			value += (encoded_byte & 127) * multiplier;
			multiplier *= 128;
			if ( multiplier > 128*128*128 )
				{
				// This is definitely a protocol violation
				this->zeek_analyzer()->AnalyzerViolation("malformed MQTT 'remaining length': too large");
				return 0;
				}
			}

		return value;
		%}
};
