# $Id:$

%extern{
#include "dns_pac.h"	// for DNS_Conn
%}

%include bro.pac

analyzer DNS_on_TCP withcontext {
	connection:	DNS_TCP_Conn;
	flow:		DNS_TCP_Flow;
};

type DNS_TCP_PDU(is_orig: bool) = record {
	msglen:		uint16;
	msg:		bytestring &length = msglen;
} &byteorder = bigendian, &length = 2 + msglen, &let {
	deliver: bool = $context.connection.deliver_dns_message(is_orig, msg);
};

connection DNS_TCP_Conn(bro_analyzer: BroAnalyzer) {
	upflow = DNS_TCP_Flow(true);
	downflow = DNS_TCP_Flow(false);

	%member{
		DNS::DNS_Conn *abstract_dns_connection_;
	%}

	%init{
		abstract_dns_connection_ = new DNS::DNS_Conn(bro_analyzer);
	%}

	%cleanup{
		delete abstract_dns_connection_;
		abstract_dns_connection_ = 0;
	%}

	function deliver_dns_message(is_orig: bool, msg: const_bytestring): bool
		%{
		abstract_dns_connection_->NewData(is_orig, msg.begin(), msg.end());
		return true;
		%}
};

flow DNS_TCP_Flow(is_orig: bool) {
	flowunit = DNS_TCP_PDU(is_orig) withcontext(connection, this);
};
