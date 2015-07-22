type TAG = RE/[[:alnum:][:punct:]]+/;
type CONTENT = RE/[^\r\n]*/;
type SPACING = RE/[ ]+/;
type OPTIONALSPACING = RE/[ ]*/;
type NEWLINE = RE/[\r\n]+/;

type IMAP_PDU(is_orig: bool) = IMAP_TOKEN(is_orig)[] &until($input.length() == 0);

type IMAP_TOKEN(is_orig: bool) = record {
	tag : TAG;
	: SPACING;
	command: TAG;
	: OPTIONALSPACING;
	tagcontent: CONTENT;
	: NEWLINE;
};

