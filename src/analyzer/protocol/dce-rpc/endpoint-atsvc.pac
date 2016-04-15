
type ATSVC_Request(unicode: bool, opnum: uint8) = record {
	empty: padding[1];
	op: case opnum of {
		0       -> add     : ATSVC_NetrJobAdd(unicode);
		default -> unknown : bytestring &restofdata;
	};
};

type ATSVC_String_Pointer(unicode: bool) = record {
	referent_id  : uint32;
	max_count    : uint32;
	offset       : uint32;
	actual_count : uint32;
	string       : bytestring &length=max_count;
};

type ATSVC_NetrJobAdd(unicode: bool) = record {
	server        : ATSVC_String_Pointer(unicode);
	unknown       : padding[2];
	job_time      : uint32;
	days_of_month : uint32;
	days_of_week  : uint8;
	flags         : uint8;
	unknown2      : padding[2];
	command       : ATSVC_String_Pointer(unicode);
};

type ATSVC_Reply(unicode: bool, opnum: uint16) = record {
	op: case opnum of {
		0       -> add:     ATSVC_JobID(unicode);
		default -> unknown: bytestring &restofdata;
	};
};

type ATSVC_JobID(unicode: bool) = record {
	id     : uint32;
	status : uint32;
};
