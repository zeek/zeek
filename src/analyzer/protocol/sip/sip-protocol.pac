type SIP_TOKEN  = RE/[^()<>@,;:\\"\/\[\]?={} \t]+/;
type SIP_WS     = RE/[ \t]*/;
type SIP_URI    = RE/[[:alnum:]@[:punct:]]+/;

type SIP_PDU(is_orig: bool) = case is_orig of {
	true  ->	request:	SIP_Request;
	false ->	reply:		SIP_Reply;
};

type SIP_Request = record {
	request:	SIP_RequestLine &oneline;
	msg:		SIP_Message;
};

type SIP_Reply = record {
	reply:		SIP_ReplyLine &oneline;
	msg:		SIP_Message;
};

type SIP_RequestLine = record {
	method:		SIP_TOKEN;
	:		SIP_WS;
	uri:		SIP_URI;
	:		SIP_WS;
	version:	SIP_Version &restofdata;
} &oneline;

type SIP_ReplyLine = record {
	version:	SIP_Version;
	:		SIP_WS;
	status:		SIP_Status;
	:		SIP_WS;
	reason:		bytestring &restofdata;
} &oneline;

type SIP_Status = record {
	stat_str:	RE/[0-9]{3}/;
} &let {
	stat_num: int = bytestring_to_int(stat_str, 10);
};

type SIP_Version = record {
	:		"SIP/";
	vers_str:	RE/[0-9]+\.[0-9]+/;
} &let {
	vers_num:	double = bytestring_to_double(vers_str);
};

type SIP_Headers = SIP_Header[] &until($input.length() == 0);

type SIP_Message = record {
	headers:	SIP_Headers;
	body:		SIP_Body;
};

type SIP_HEADER_NAME = RE/[^: \t]+/;
type SIP_Header = record {
	name:	SIP_HEADER_NAME;
	:	SIP_WS;
	:	":";
	:	SIP_WS;
	value:	bytestring &restofdata;
} &oneline;

type SIP_Body = record {
	 body:	bytestring &length = $context.flow.get_content_length();
};
