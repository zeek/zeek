// $Id:$
//
// See the file "COPYING" in the main distribution directory for copyright.

#include "TCP_Rewriter.h"
#include "UDP_Rewriter.h"

// The following two are called from .bif's to obtain handle of Rewriter.
Rewriter* get_trace_rewriter(Val* conn_val)
	{
	Connection* conn = (Connection*) conn_val->AsRecordVal()->GetOrigin();
	return get_trace_rewriter(conn);
	}

Rewriter* get_trace_rewriter(Connection* conn)
	{
	if ( ! conn ||
	     (conn->ConnTransport() != TRANSPORT_TCP &&
	      conn->ConnTransport() != TRANSPORT_UDP) )
		internal_error("connection for the trace rewriter does not exist");

	Rewriter* rewriter = conn->TraceRewriter();
	if ( rewriter )
		return rewriter;

	if ( ! transformed_pkt_dump )
		return 0;	// okay if we don't have an output file

	else if ( ! conn->RewritingTrace() )
		builtin_run_time("flag rewriting_..._trace is not set properly");
	else
		internal_error("trace rewriter not initialized");

	return 0;
	}
