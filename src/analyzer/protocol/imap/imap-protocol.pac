# commands that we support parsing. The numbers do not really mean anything
# in this case
enum ImapCommand {
	CMD_CAPABILITY,
	CMD_UNKNOWN
}

type TAG = RE/[[:alnum:][:punct:]]+/;
type CONTENT = RE/[^\r\n]*/;
type SPACING = RE/[ ]+/;
type OPTIONALSPACING = RE/[ ]*/;
type NEWLINE = RE/[\r\n]+/;
type OPTIONALNEWLINE = RE/[\r\n]*/;

type IMAP_PDU(is_orig: bool) = ImapToken(is_orig)[] &until($input.length() == 0);

type ImapToken(is_orig: bool) = record {
	tag : TAG;
	: SPACING;
	command: TAG;
	: OPTIONALSPACING;
	client_or_server: case is_orig of {
		true -> client: UnknownCommand(this) ;
		false -> server: ServerContentText(this);
	} &requires(pcommand) ;
} &let {
	pcommand: int = $context.connection.determine_command(is_orig, tag, command);
};

type ServerContentText(rec: ImapToken) = case rec.pcommand of {
	CMD_CAPABILITY -> capability: ServerCapability(rec);
	default -> unknown: UnknownCommand(rec);
};

type Capability = record {
	cap: TAG;
	: OPTIONALSPACING;
	nl: OPTIONALNEWLINE;
};

type ServerCapability(rec: ImapToken) = record {
	capabilities: Capability[] &until($context.connection.strlen($element.nl) > 0);
};

type UnknownCommand(rec: ImapToken) = record {
	tagcontent: CONTENT;
	: NEWLINE;
};

refine connection IMAP_Conn += {

	function determine_command(is_orig: bool, tag: bytestring, command: bytestring): int
		%{
		string cmdstr = std_str(command);
		std::transform(cmdstr.begin(), cmdstr.end(), cmdstr.begin(), ::tolower);
		string tagstr = std_str(tag);

		if ( !is_orig && cmdstr == "capability" && tag == "*" ) {
			return CMD_CAPABILITY;
		}

		return CMD_UNKNOWN;
		%}

	function strlen(str: bytestring): int
		%{
		return str.length();
		%}

};
