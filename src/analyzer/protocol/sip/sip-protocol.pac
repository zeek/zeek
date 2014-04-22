enum ExpectBody {
        BODY_EXPECTED,
	BODY_NOT_EXPECTED,
        BODY_MAYBE,
};

type SIP_TOKEN  = RE/[^()<>@,;:\\"\/\[\]?={} \t]+/;
type SIP_WS     = RE/[ \t]*/;
type SIP_COLON	= RE/:/;
type SIP_TO_EOL = RE/[^\r\n]*/;
type SIP_URI    = RE/[[:alnum:]@[:punct:]]+/;

type SIP_PDU(is_orig: bool) = case is_orig of {
     true ->         request:        SIP_Request;
     false ->        reply:          SIP_Reply;
};

type SIP_Request = record {
     request:        SIP_RequestLine;
     msg:            SIP_Message;
};

type SIP_Reply = record {
     reply:          SIP_ReplyLine;
     msg:            SIP_Message;
};

type SIP_RequestLine = record {
     method:         SIP_TOKEN;
     :               SIP_WS;
     uri:            SIP_URI;
     :               SIP_WS;
     version:        SIP_Version;
} &oneline;

type SIP_ReplyLine = record {
     version:        SIP_Version;
     :               SIP_WS;
     status:         SIP_Status;
     :               SIP_WS;
     reason:         SIP_TO_EOL;
} &oneline;

type SIP_Status = record {
     stat_str:       RE/[0-9]{3}/;
} &let {
        stat_num: int = bytestring_to_int(stat_str, 10);
};

type SIP_Version = record {
     :               "SIP/";
     vers_str:       RE/[0-9]+\.[0-9]+/;
} &let {
        vers_num: double = bytestring_to_double(vers_str);
};

type SIP_Headers = SIP_Header[] &until($input.length() == 0);

type SIP_Message = record {
     headers:        SIP_Headers;
     body:           SIP_Body;
};

type SIP_HEADER_NAME = RE/([^: \t]+)/;
type SIP_Header = record {
     :               padding[2];
     name:           SIP_HEADER_NAME;
     :		     SIP_COLON;
     :               SIP_WS;
     value:          SIP_TO_EOL;
} &oneline &byteorder=bigendian;

type SIP_Body() = record {
      body: bytestring &chunked, &length = $context.flow.get_content_length();
};
