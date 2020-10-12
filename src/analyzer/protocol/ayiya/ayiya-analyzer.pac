%extern{
#include "Sessions.h"
#include "Conn.h"
#include "AYIYA.h"
%}

connection AYIYA_Conn(zeek_analyzer: ZeekAnalyzer)
	{
	upflow = AYIYA_Flow;
	downflow = AYIYA_Flow;
	};

flow AYIYA_Flow
	{
	datagram = PDU withcontext(connection, this);

	function process_ayiya(pdu: PDU): bool
		%{
		zeek::Connection* c = connection()->zeek_analyzer()->Conn();
		std:shared_ptr<zeek::EncapsulationStack> e = c->GetEncapsulation();

		if ( e && e->Depth() >= zeek::BifConst::Tunnel::max_depth )
			{
			zeek::reporter->Weird(c, "tunnel_depth");
			return false;
			}

		if ( ${pdu.op} != 1 )
			{
			// 1 is the "forward" command.
			return false;
			}

		if ( ${pdu.next_header} != IPPROTO_IPV6 &&
		     ${pdu.next_header} != IPPROTO_IPV4 )
			{
			zeek::reporter->Weird(c, "ayiya_tunnel_non_ip");
			return false;
			}

		if ( ${pdu.packet}.length() < (int)sizeof(struct ip) )
			{
			connection()->zeek_analyzer()->ProtocolViolation(
			    "Truncated AYIYA", (const char*) ${pdu.packet}.data(),
			    ${pdu.packet}.length());
			return false;
			}

		const struct ip* ip = (const struct ip*) ${pdu.packet}.data();

		if ( ( ${pdu.next_header} == IPPROTO_IPV6 && ip->ip_v != 6 ) ||
		     ( ${pdu.next_header} == IPPROTO_IPV4 && ip->ip_v != 4) )
			{
			connection()->zeek_analyzer()->ProtocolViolation(
			    "AYIYA next header mismatch", (const char*)${pdu.packet}.data(),
			     ${pdu.packet}.length());
			return false;
			}

		static_cast<zeek::analyzer::ayiya::AYIYA_Analyzer*>(connection()->zeek_analyzer())->SetInnerInfo(${pdu.hdr_len}, ${pdu.next_header});

		return true;
		%}

	};

refine typeattr PDU += &let {
	proc_ayiya = $context.flow.process_ayiya(this);
};
