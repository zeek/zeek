type XML_START = RE/</;
type XML_END = RE/>/;
type XML_NAME = RE/\/?[?:[:alnum:]]+/;
type XML_REST = RE/[^<>]*/;
type SPACING = RE/[ \r\n]*/;
type CONTENT = RE/[^<>]*/;

type XMPP_PDU(is_orig: bool) = XMPP_TOKEN(is_orig)[] &until($input.length() == 0);

type XMPP_TOKEN(is_orig: bool) = record {
	: SPACING;
	: XML_START;
	name: XML_NAME;
	rest: XML_REST;
	: XML_END;
	tagcontent: CONTENT;
};

