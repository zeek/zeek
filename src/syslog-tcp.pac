
%extern{
#include "syslog_pac.h"
%}

%include bro.pac
%include binpac.pac
%include syslog-protocol.pac

# TCP support
analyzer Syslog_TCP withcontext {
	connection:	Syslog_TCP_Conn;
	flow:		Syslog_TCP_Flow;
};

# We are punting on this for now and essentially only implementing 
# "Octet Stuffing" which is basically using a line based delimiter to
# define PDU's for messages within the stream.
type Syslog_TCP_Message(is_orig: bool) = record {
	msg: bytestring &oneline;
	#first_byte:  uint8;
	#data: case $context.connection.is_octet_counting(first_byte) of {
	#	true  -> stuffing : Octet_Stuffing(is_orig, first_byte) &oneline;
	#	false -> counting : Octet_Counting(is_orig, first_byte);
	#} &oneline;
} &oneline, &let {
	deliver: bool = $context.connection.deliver_syslog_message(is_orig, msg);
};

type Octet_Counting(is_orig: bool, first_byte: uint8) = record {
	msglen:     RE/[0-9]*/;
	:           " ";
	msg:        bytestring &length=real_msglen;
} &let {
	real_msglen: int = $context.connection.calc_real_msglen(first_byte, msglen);
	deliver: bool = $context.connection.deliver_syslog_message(is_orig, msg);
};

type Octet_Stuffing(is_orig: bool, first_byte: uint8) = record {
	msg:        bytestring &oneline;
} &let {
	deliver: bool = $context.connection.deliver_syslog_message(is_orig, msg);
};

connection Syslog_TCP_Conn(bro_analyzer: BroAnalyzer)
{
	upflow = Syslog_TCP_Flow(true);
	downflow = Syslog_TCP_Flow(false);
	
	%member{
		Syslog::Syslog_Conn *abstract_syslog_connection_;
	%}

	%init{
		abstract_syslog_connection_ = new Syslog::Syslog_Conn(bro_analyzer);
	%}
	
	%cleanup{
		delete abstract_syslog_connection_;
		abstract_syslog_connection_ = 0;
	%}
	
	function deliver_syslog_message(is_orig: bool, msg: const_bytestring): bool
		%{
		abstract_syslog_connection_->NewData(is_orig, msg.begin(), msg.end());
		return true;
		%}
		
	function is_octet_counting(first_byte: uint8): bool
		%{
		return ( 49 <= first_byte && first_byte <= 57 );
		%}
	
	function calc_real_msglen(first_byte: uint8, msglen: bytestring): int
		%{
		//char len_string[msglen.length()+2];
		//len_string[0] = first_byte;
		//len_string[1] = msglen.begin();
		//len_string[1+msglen.length()+1] = 0;
		//return atoi((const char *) len_string);
		return 0;
		%}
};

flow Syslog_TCP_Flow(is_orig: bool) {
	flowunit = Syslog_TCP_Message(is_orig) withcontext(connection, this);
}

