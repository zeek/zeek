// See the file "COPYING" in the main distribution directory for copyright.

#include "Portmap.h"
#include "NetVar.h"
#include "XDR.h"
#include "Event.h"

#include "events.bif.h"

#include "zeek-config.h"

using namespace analyzer::rpc;

#define PMAPPROC_NULL 0
#define PMAPPROC_SET 1
#define PMAPPROC_UNSET 2
#define PMAPPROC_GETPORT 3
#define PMAPPROC_DUMP 4
#define PMAPPROC_CALLIT 5

int PortmapperInterp::RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n)
	{
	if ( c->Program() != 100000 )
		Weird("bad_RPC_program");

	switch ( c->Proc() ) {
	case PMAPPROC_NULL:
		break;

	case PMAPPROC_SET:
		{
		Val* m = ExtractMapping(buf, n);
		if ( ! m )
			return 0;
		c->AddVal(m);
		}
		break;

	case PMAPPROC_UNSET:
		{
		Val* m = ExtractMapping(buf, n);
		if ( ! m )
			return 0;
		c->AddVal(m);
		}
		break;

	case PMAPPROC_GETPORT:
		{
		Val* pr = ExtractPortRequest(buf, n);
		if ( ! pr )
			return 0;
		c->AddVal(pr);
		}
		break;

	case PMAPPROC_DUMP:
		break;

	case PMAPPROC_CALLIT:
		{
		Val* call_it = ExtractCallItRequest(buf, n);
		if ( ! call_it )
			return 0;
		c->AddVal(call_it);
		}
		break;

	default:
		return 0;
	}

	return 1;
	}

int PortmapperInterp::RPC_BuildReply(RPC_CallInfo* c, BifEnum::rpc_status status,
				     const u_char*& buf, int& n,
				     double start_time, double last_time,
				     int reply_len)
	{
	EventHandlerPtr event;
	Val *reply = 0;
	int success = (status == BifEnum::RPC_SUCCESS);

	switch ( c->Proc() ) {
	case PMAPPROC_NULL:
		event = success ? pm_request_null : pm_attempt_null;
		break;

	case PMAPPROC_SET:
		if ( success )
			{
			uint32_t status = extract_XDR_uint32(buf, n);
			if ( ! buf )
				return 0;

			reply = val_mgr->GetBool(status);
			event = pm_request_set;
			}
		else
			event = pm_attempt_set;

		break;

	case PMAPPROC_UNSET:
		if ( success )
			{
			uint32_t status = extract_XDR_uint32(buf, n);
			if ( ! buf )
				return 0;

			reply = val_mgr->GetBool(status);
			event = pm_request_unset;
			}
		else
			event = pm_attempt_unset;

		break;

	case PMAPPROC_GETPORT:
		if ( success )
			{
			uint32_t port = extract_XDR_uint32(buf, n);
			if ( ! buf )
				return 0;

			RecordVal* rv = c->RequestVal()->AsRecordVal();
			Val* is_tcp = rv->Lookup(2);
			reply = val_mgr->GetPort(CheckPort(port),
					is_tcp->IsOne() ?
						TRANSPORT_TCP : TRANSPORT_UDP);
			event = pm_request_getport;
			}
		else
			event = pm_attempt_getport;
		break;

	case PMAPPROC_DUMP:
		event = success ? pm_request_dump : pm_attempt_dump;
		if ( success )
			{
			TableVal* mappings = new TableVal({NewRef{}, pm_mappings});
			uint32_t nmap = 0;

			// Each call in the loop test pulls the next "opted"
			// element to see if there are more mappings.
			while ( extract_XDR_uint32(buf, n) && buf )
				{
				Val* m = ExtractMapping(buf, n);
				if ( ! m )
					break;

				Val* index = val_mgr->GetCount(++nmap);
				mappings->Assign(index, m);
				Unref(index);
				}

			if ( ! buf )
				{
				Unref(mappings);
				return 0;
				}

			reply = mappings;
			event = pm_request_dump;
			}
		else
			event = pm_attempt_dump;
		break;

	case PMAPPROC_CALLIT:
		if ( success )
			{
			uint32_t port = extract_XDR_uint32(buf, n);
			int reply_n;
			const u_char* opaque_reply =
				extract_XDR_opaque(buf, n, reply_n);
			if ( ! opaque_reply )
				return 0;

			reply = val_mgr->GetPort(CheckPort(port), TRANSPORT_UDP);
			event = pm_request_callit;
			}
		else
			event = pm_attempt_callit;
		break;

	default:
		return 0;
	}

	Event(event, c->TakeRequestVal(), status, reply);
	return 1;
	}

Val* PortmapperInterp::ExtractMapping(const u_char*& buf, int& len)
	{
	RecordVal* mapping = new RecordVal(pm_mapping);

	mapping->Assign(0, val_mgr->GetCount(extract_XDR_uint32(buf, len)));
	mapping->Assign(1, val_mgr->GetCount(extract_XDR_uint32(buf, len)));

	int is_tcp = extract_XDR_uint32(buf, len) == IPPROTO_TCP;
	uint32_t port = extract_XDR_uint32(buf, len);
	mapping->Assign(2, val_mgr->GetPort(CheckPort(port),
			is_tcp ? TRANSPORT_TCP : TRANSPORT_UDP));

	if ( ! buf )
		{
		Unref(mapping);
		return 0;
		}

	return mapping;
	}

Val* PortmapperInterp::ExtractPortRequest(const u_char*& buf, int& len)
	{
	RecordVal* pr = new RecordVal(pm_port_request);

	pr->Assign(0, val_mgr->GetCount(extract_XDR_uint32(buf, len)));
	pr->Assign(1, val_mgr->GetCount(extract_XDR_uint32(buf, len)));

	int is_tcp = extract_XDR_uint32(buf, len) == IPPROTO_TCP;
	pr->Assign(2, val_mgr->GetBool(is_tcp));
	(void) extract_XDR_uint32(buf, len);	// consume the bogus port

	if ( ! buf )
		{
		Unref(pr);
		return 0;
		}

	return pr;
	}

Val* PortmapperInterp::ExtractCallItRequest(const u_char*& buf, int& len)
	{
	RecordVal* c = new RecordVal(pm_callit_request);

	c->Assign(0, val_mgr->GetCount(extract_XDR_uint32(buf, len)));
	c->Assign(1, val_mgr->GetCount(extract_XDR_uint32(buf, len)));
	c->Assign(2, val_mgr->GetCount(extract_XDR_uint32(buf, len)));

	int arg_n;
	(void) extract_XDR_opaque(buf, len, arg_n);
	c->Assign(3, val_mgr->GetCount(arg_n));

	if ( ! buf )
		{
		Unref(c);
		return 0;
		}

	return c;
	}

uint32_t PortmapperInterp::CheckPort(uint32_t port)
	{
	if ( port >= 65536 )
		{
		if ( pm_bad_port )
			{
			analyzer->ConnectionEventFast(pm_bad_port, {
				analyzer->BuildConnVal(),
				val_mgr->GetCount(port),
			});
			}

		port = 0;
		}

	return port;
	}

void PortmapperInterp::Event(EventHandlerPtr f, Val* request, BifEnum::rpc_status status, Val* reply)
	{
	if ( ! f )
		{
		Unref(request);
		Unref(reply);
		return;
		}

	val_list vl;

	vl.push_back(analyzer->BuildConnVal());

	if ( status == BifEnum::RPC_SUCCESS )
		{
		if ( request )
			vl.push_back(request);
		if ( reply )
			vl.push_back(reply);
		}
	else
		{
		vl.push_back(BifType::Enum::rpc_status->GetVal(status).release());
		if ( request )
			vl.push_back(request);
		}

	analyzer->ConnectionEventFast(f, std::move(vl));
	}

Portmapper_Analyzer::Portmapper_Analyzer(Connection* conn)
: RPC_Analyzer("PORTMAPPER", conn, new PortmapperInterp(this))
	{
	orig_rpc = resp_rpc = 0;
	}

Portmapper_Analyzer::~Portmapper_Analyzer()
	{
	}

void Portmapper_Analyzer::Init()
	{
	RPC_Analyzer::Init();

	if ( Conn()->ConnTransport() == TRANSPORT_TCP )
		{
		orig_rpc = new Contents_RPC(Conn(), true, interp);
		resp_rpc = new Contents_RPC(Conn(), false, interp);
		AddSupportAnalyzer(orig_rpc);
		AddSupportAnalyzer(resp_rpc);
		}
	}
