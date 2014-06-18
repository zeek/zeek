
type RADIUS_PDU(is_orig: bool) = record {
	code: uint8;
	trans_id: uint8;
	length: uint16;
	authenticator: bytestring &length=16;
	attributes: RADIUS_Attribute(trans_id)[] &until($input.length() == 0);
} &byteorder=bigendian;

type RADIUS_Attribute(trans_id: uint8) = record {
	code: uint8;
	length: uint8;
	value: bytestring &length=length-2;
};
