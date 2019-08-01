enum Openvpn_Opcode {
	P_CONTROL_HARD_RESET_CLIENT_V1	= 0x01,
	P_CONTROL_HARD_RESET_SERVER_V1	= 0x02,
	P_CONTROL_SOFT_RESET_V1		= 0x03,
	P_CONTROL_V1			= 0x04,
	P_ACK_V1			= 0x05,
	P_DATA_V1			= 0x06,
	P_CONTROL_HARD_RESET_CLIENT_V2	= 0x07,
	P_CONTROL_HARD_RESET_SERVER_V2	= 0x08,
	P_DATA_V2			= 0x09,
};

type OpenVPNPDU(is_orig: bool) = record {
	records: OpenVPNRecord(is_orig)[] &transient;
};

type OpenVPNRecord(is_orig: bool) = record {
	MessageType : uint8;
	rec: OpenVPNData(this) &requires(opcode, key_id);
} &let {
	opcode : uint8 = (MessageType >> 3);  # The high 5 bits
	key_id : uint8  = (MessageType & 0x07);  # The low 3 bits
} &byteorder = bigendian;

type OpenVPNData(rec: OpenVPNRecord) = case rec.opcode of {
	P_CONTROL_V1 -> control_v1: ControlV1(rec);
	default -> unknown: bytestring &restofdata &transient;
}

type ControlV1(rec: OpenVPNRecord) = record {
	session_id : bytestring &length=8;
	packet_id_array_len : uint8;
	packet_id_array : uint32[packet_id_array_len];
	rs: case  packet_id_array_len of {
		0 -> nothing: bytestring &length=0;
		default -> remote_session_id: bytestring &length=8;
	};
	packet_id : uint32;
	ssl_data : bytestring &restofdata;
} &let {
	ssl_data_forwarded : bool =
		$context.connection.forward_ssl(ssl_data, rec.is_orig);
};

refine connection OpenVPN_Conn += {

	function forward_ssl(ssl_data: bytestring, is_orig: bool) : bool
		%{
		bro_analyzer()->ForwardSSLData(ssl_data.length(), reinterpret_cast<const u_char*>(ssl_data.data()), is_orig);
		return true;
		%}

};
