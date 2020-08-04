// See the file "COPYING" in the main distribution directory for copyright.

#include "Portmap.h"
#include "NetVar.h"
#include "XDR.h"
#include "Event.h"

#include "events.bif.h"

#include "zeek-config.h"

#define PMAPPROC_NULL 0
#define PMAPPROC_SET 1
#define PMAPPROC_UNSET 2
#define PMAPPROC_GETPORT 3
#define PMAPPROC_DUMP 4
#define PMAPPROC_CALLIT 5

namespace zeek::analyzer::rpc {
namespace detail {

bool PortmapperInterp::RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n)
	{
	if ( c->Program() != 100000 )
		Weird("bad_RPC_program");

	switch ( c->Proc() ) {
	case PMAPPROC_NULL:
		break;

	case PMAPPROC_SET:
		{
		auto m = ExtractMapping(buf, n);
		if ( ! m )
			return false;
		c->AddVal(std::move(m));
		}
		break;

	case PMAPPROC_UNSET:
		{
		auto m = ExtractMapping(buf, n);
		if ( ! m )
			return false;
		c->AddVal(std::move(m));
		}
		break;

	case PMAPPROC_GETPORT:
		{
		auto pr = ExtractPortRequest(buf, n);
		if ( ! pr )
			return false;
		c->AddVal(std::move(pr));
		}
		break;

	case PMAPPROC_DUMP:
		break;

	case PMAPPROC_CALLIT:
		{
		auto call_it = ExtractCallItRequest(buf, n);
		if ( ! call_it )
			return false;
		c->AddVal(std::move(call_it));
		}
		break;

	default:
		return false;
	}

	return true;
	}

bool PortmapperInterp::RPC_BuildReply(RPC_CallInfo* c, BifEnum::rpc_status status,
				     const u_char*& buf, int& n,
				     double start_time, double last_time,
				     int reply_len)
	{
	zeek::EventHandlerPtr event;
	zeek::ValPtr reply;
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
				return false;

			reply = zeek::val_mgr->Bool(status);
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
				return false;

			reply = zeek::val_mgr->Bool(status);
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
				return false;

			zeek::RecordVal* rv = c->RequestVal()->AsRecordVal();
			const auto& is_tcp = rv->GetField(2);
			reply = zeek::val_mgr->Port(CheckPort(port), is_tcp->IsOne() ?
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
			static auto pm_mappings = zeek::id::find_type<zeek::TableType>("pm_mappings");
			auto mappings = zeek::make_intrusive<zeek::TableVal>(pm_mappings);
			uint32_t nmap = 0;

			// Each call in the loop test pulls the next "opted"
			// element to see if there are more mappings.
			while ( extract_XDR_uint32(buf, n) && buf )
				{
				auto m = ExtractMapping(buf, n);
				if ( ! m )
					break;

				auto index = zeek::val_mgr->Count(++nmap);
				mappings->Assign(std::move(index), std::move(m));
				}

			if ( ! buf )
				return false;

			reply = std::move(mappings);
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
				return false;

			reply = zeek::val_mgr->Port(CheckPort(port), TRANSPORT_UDP);
			event = pm_request_callit;
			}
		else
			event = pm_attempt_callit;
		break;

	default:
		return false;
	}

	Event(event, c->TakeRequestVal(), status, std::move(reply));
	return true;
	}

zeek::ValPtr PortmapperInterp::ExtractMapping(const u_char*& buf, int& len)
	{
	static auto pm_mapping = zeek::id::find_type<zeek::RecordType>("pm_mapping");
	auto mapping = zeek::make_intrusive<zeek::RecordVal>(pm_mapping);

	mapping->Assign(0, zeek::val_mgr->Count(extract_XDR_uint32(buf, len)));
	mapping->Assign(1, zeek::val_mgr->Count(extract_XDR_uint32(buf, len)));

	bool is_tcp = extract_XDR_uint32(buf, len) == IPPROTO_TCP;
	uint32_t port = extract_XDR_uint32(buf, len);
	mapping->Assign(2, zeek::val_mgr->Port(CheckPort(port), is_tcp ? TRANSPORT_TCP : TRANSPORT_UDP));

	if ( ! buf )
		return nullptr;

	return mapping;
	}

zeek::ValPtr PortmapperInterp::ExtractPortRequest(const u_char*& buf, int& len)
	{
	static auto pm_port_request = zeek::id::find_type<zeek::RecordType>("pm_port_request");
	auto pr = zeek::make_intrusive<zeek::RecordVal>(pm_port_request);

	pr->Assign(0, zeek::val_mgr->Count(extract_XDR_uint32(buf, len)));
	pr->Assign(1, zeek::val_mgr->Count(extract_XDR_uint32(buf, len)));

	bool is_tcp = extract_XDR_uint32(buf, len) == IPPROTO_TCP;
	pr->Assign(2, zeek::val_mgr->Bool(is_tcp));
	(void) extract_XDR_uint32(buf, len);	// consume the bogus port

	if ( ! buf )
		return nullptr;

	return pr;
	}

zeek::ValPtr PortmapperInterp::ExtractCallItRequest(const u_char*& buf, int& len)
	{
	static auto pm_callit_request = zeek::id::find_type<zeek::RecordType>("pm_callit_request");
	auto c = zeek::make_intrusive<zeek::RecordVal>(pm_callit_request);

	c->Assign(0, zeek::val_mgr->Count(extract_XDR_uint32(buf, len)));
	c->Assign(1, zeek::val_mgr->Count(extract_XDR_uint32(buf, len)));
	c->Assign(2, zeek::val_mgr->Count(extract_XDR_uint32(buf, len)));

	int arg_n;
	(void) extract_XDR_opaque(buf, len, arg_n);
	c->Assign(3, zeek::val_mgr->Count(arg_n));

	if ( ! buf )
		return nullptr;

	return c;
	}

uint32_t PortmapperInterp::CheckPort(uint32_t port)
	{
	if ( port >= 65536 )
		{
		if ( pm_bad_port )
			{
			analyzer->EnqueueConnEvent(pm_bad_port,
				analyzer->ConnVal(),
				zeek::val_mgr->Count(port)
			);
			}

		port = 0;
		}

	return port;
	}

void PortmapperInterp::Event(zeek::EventHandlerPtr f, zeek::ValPtr request, BifEnum::rpc_status status, zeek::ValPtr reply)
	{
	if ( ! f )
		return;

	zeek::Args vl;

	vl.emplace_back(analyzer->ConnVal());

	if ( status == BifEnum::RPC_SUCCESS )
		{
		if ( request )
			vl.emplace_back(std::move(request));
		if ( reply )
			vl.emplace_back(std::move(reply));
		}
	else
		{
		vl.emplace_back(zeek::BifType::Enum::rpc_status->GetEnumVal(status));

		if ( request )
			vl.emplace_back(std::move(request));
		}

	analyzer->EnqueueConnEvent(f, std::move(vl));
	}

} // namespace detail

Portmapper_Analyzer::Portmapper_Analyzer(zeek::Connection* conn)
: RPC_Analyzer("PORTMAPPER", conn, new detail::PortmapperInterp(this))
	{
	orig_rpc = resp_rpc = nullptr;
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

} // namespace zeek::analyzer::rpc
