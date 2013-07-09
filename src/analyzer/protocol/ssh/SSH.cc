// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include <ctype.h>

#include "NetVar.h"
#include "SSH.h"
#include "Event.h"
#include "analyzer/protocol/tcp/ContentLine.h"

#include "events.bif.h"

using namespace analyzer::ssh;

SSH_Analyzer::SSH_Analyzer(Connection* c)
: tcp::TCP_ApplicationAnalyzer("SSH", c)
	{
	orig = new tcp::ContentLine_Analyzer(c, true);
	orig->SetSkipPartial(true);
	orig->SetCRLFAsEOL(LF_as_EOL);
	AddSupportAnalyzer(orig);

	resp = new tcp::ContentLine_Analyzer(c, false);
	resp->SetSkipPartial(true);
	resp->SetCRLFAsEOL(LF_as_EOL);
	AddSupportAnalyzer(resp);
	}

void SSH_Analyzer::DeliverStream(int length, const u_char* data, bool is_orig)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(length, data, is_orig);

	// We're all done processing this endpoint - flag it as such,
	// before we even determine whether we have any event generation
	// work to do, to make sure we don't do any further work on it.
	if ( is_orig )
		orig->SetSkipDeliveries(true);
	else
		resp->SetSkipDeliveries(true);

	if ( TCP() )
		{
		// Don't try to parse version if there has already been a gap.
		tcp::TCP_Endpoint* endp = is_orig ? TCP()->Orig() : TCP()->Resp();
		if ( endp->HadGap() )
			return;
		}

	const char* line = (const char*) data;

	// The SSH identification looks like this:
	//
	//     SSH-<protocolmajor>.<protocolminor>-<version>\n
	//
	// We're interested in the "version" part here.

	if ( length < 4 || memcmp(line, "SSH-", 4) != 0 )
		{
		Weird("malformed_ssh_identification");
		ProtocolViolation("malformed ssh identification", line, length);
		return;
		}

	int i;
	for ( i = 4; i < length && line[i] != '-'; ++i )
		;

	if ( TCP() )
		{
		if ( length >= i )
			{
			IPAddr dst;

			if ( is_orig )
				dst = TCP()->Orig()->dst_addr;
			else
				dst = TCP()->Resp()->dst_addr;

			if ( Conn()->VersionFoundEvent(dst, line + i,
							length - i) )
				ProtocolConfirmation();
			else
				ProtocolViolation("malformed ssh version",
							line, length);
			}
		else
			{
			Weird("malformed_ssh_version");
			ProtocolViolation("malformed ssh version", line, length);
			}
		}

	// Generate SSH events.
	EventHandlerPtr event = is_orig ?
				ssh_client_version : ssh_server_version;
	if ( ! event )
		return;

	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	vl->append(new StringVal(length, line));

	ConnectionEvent(event, vl);
	}
