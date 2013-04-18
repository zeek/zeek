// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include <stdlib.h>
#include <string>
#include <map>

using namespace std;

#include "DCE_RPC.h"
#include "Sessions.h"

#include "analyzer/Manager.h"

#include "events.bif.h"

using namespace analyzer::dce_rpc;

#define xbyte(b, n) (((const u_char*) (b))[n])

#define extract_uint16(little_endian, bytes) \
	((little_endian) ? \
	 uint16(xbyte(bytes, 0)) | ((uint16(xbyte(bytes, 1))) << 8) : \
	 uint16(xbyte(bytes, 1)) | ((uint16(xbyte(bytes, 0))) << 8))

static int uuid_index[] = {
	3, 2, 1, 0,
	5, 4, 7, 6,
	8, 9, 10, 11,
	12, 13, 14, 15
};

const char* analyzer::dce_rpc::uuid_to_string(const u_char* uuid_data)
	{
	static char s[1024];
	char* sp = s;

	for ( int i = 0; i < 16; ++i )
		{
		if ( i == 4 || i == 6 || i == 8 || i == 10 )
			sp += snprintf(sp, s + sizeof(s) - sp, "-");

		int j = uuid_index[i];
		sp += snprintf(sp, s + sizeof(s) - sp, "%02x", uuid_data[j]);
		}

	return s;
	}

UUID::UUID()
	{
	memset(data, 0, 16);
	s = uuid_to_string(data);
	}

UUID::UUID(const u_char d[16])
	{
	memcpy(data, d, 16);
	s = uuid_to_string(data);
	}

UUID::UUID(const binpac::bytestring& uuid)
	{
	if ( uuid.length() != 16 )
		reporter->InternalError("UUID length error");
	memcpy(data, uuid.begin(), 16);
	s = uuid_to_string(data);
	}

UUID::UUID(const char* str)
	{
	s = string(str);
	const char* sp = str;
	int i;
	for ( i = 0; i < 16; ++i )
		{
		if ( *sp == '-' )
			++sp;
		if ( ! *sp || ! *(sp+1) )
			break;

		data[uuid_index[i]] =
			(u_char) (decode_hex(*sp) * 16 + decode_hex(*(sp+1)));
		}

	if ( i != 16 )
		reporter->InternalError("invalid UUID string: %s", str);
	}

typedef map<UUID, BifEnum::dce_rpc_if_id> uuid_map_t;

static uuid_map_t& well_known_uuid_map()
	{
	static uuid_map_t the_map;
	static bool initialized = false;

	if ( initialized )
		return the_map;

	using namespace BifEnum;

	the_map[UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa")] = DCE_RPC_epmapper;

	the_map[UUID("afa8bd80-7d8a-11c9-bef4-08002b102989")] = DCE_RPC_mgmt;

	// It's said that the following interfaces are merely aliases.
	the_map[UUID("12345778-1234-abcd-ef00-0123456789ab")] = DCE_RPC_lsarpc;
	the_map[UUID("12345678-1234-abcd-ef00-01234567cffb")] = DCE_RPC_netlogon;
	the_map[UUID("12345778-1234-abcd-ef00-0123456789ac")] = DCE_RPC_samr;

	// The next group of aliases.
	the_map[UUID("4b324fc8-1670-01d3-1278-5a47bf6ee188")] = DCE_RPC_srvsvc;
	the_map[UUID("12345678-1234-abcd-ef00-0123456789ab")] = DCE_RPC_spoolss;
	the_map[UUID("45f52c28-7f9f-101a-b52b-08002b2efabe")] = DCE_RPC_winspipe;
	the_map[UUID("6bffd098-a112-3610-9833-46c3f87e345a")] = DCE_RPC_wkssvc;

	// DRS - NT directory replication service.
	the_map[UUID("e3514235-4b06-11d1-ab04-00c04fc2dcd2")] = DCE_RPC_drs;

	// "The IOXIDResolver RPC interface (formerly known as
	// IObjectExporter) is remotely used to reach the local object
	// resolver (OR)."
	the_map[UUID("99fcfec4-5260-101b-bbcb-00aa0021347a")] = DCE_RPC_oxid;

	the_map[UUID("3919286a-b10c-11d0-9ba8-00c04fd92ef5")] = DCE_RPC_lsa_ds;

	the_map[UUID("000001a0-0000-0000-c000-000000000046")] = DCE_RPC_ISCMActivator;

	initialized = true;
	return the_map;
	}

// Used to remember mapped DCE/RPC endpoints and parse the follow-up
// connections as DCE/RPC sessions.
map<dce_rpc_endpoint_addr, UUID> dce_rpc_endpoints;

static bool is_mapped_dce_rpc_endpoint(const dce_rpc_endpoint_addr& addr)
	{
	return dce_rpc_endpoints.find(addr) != dce_rpc_endpoints.end();
	}

bool is_mapped_dce_rpc_endpoint(const ConnID* id, TransportProto proto)
	{
	if ( id->dst_addr.GetFamily() == IPv6 )
		// TODO: Does the protocol support v6 addresses? #773
		return false;

	dce_rpc_endpoint_addr addr;
	addr.addr = id->dst_addr;
	addr.port = ntohs(id->dst_port);
	addr.proto = proto;

	return is_mapped_dce_rpc_endpoint(addr);
	}

static void add_dce_rpc_endpoint(const dce_rpc_endpoint_addr& addr,
					const UUID& uuid)
	{
	DEBUG_MSG("Adding endpoint %s @ %s\n",
		uuid.to_string(), addr.to_string().c_str());
	dce_rpc_endpoints[addr] = uuid;

	// FIXME: Once we can pass the cookie to the analyzer, we can get rid
	// of the dce_rpc_endpoints table.
	// FIXME: Don't hard-code the timeout.

	analyzer_mgr->ScheduleAnalyzer(IPAddr(), addr.addr, addr.port, addr.proto,
				       "DCE_RPC", 5 * 60);
	}

DCE_RPC_Header::DCE_RPC_Header(analyzer::Analyzer* a, const u_char* b)
	{
	analyzer = a;
	bytes = b;

	// This checks whether it's both the first fragment *and*
	// the last fragment.
	if ( (bytes[3] & 0x3) != 0x3 )
		{
		fragmented = 1;
		Weird("Fragmented DCE/RPC message");
		}
	else
		fragmented = 0;

	ptype = (BifEnum::dce_rpc_ptype) bytes[2];
	frag_len = extract_uint16(LittleEndian(), bytes + 8);
	}

DCE_RPC_Session::DCE_RPC_Session(analyzer::Analyzer* a)
: analyzer(a),
  if_uuid("00000000-0000-0000-0000-000000000000"),
  if_id(BifEnum::DCE_RPC_unknown_if)
	{
	opnum = -1;
	}

bool DCE_RPC_Session::LooksLikeRPC(int len, const u_char* msg)
	{
	// if ( ! is_IPC )
	//	return false;

	try
		{
		binpac::DCE_RPC_Simple::DCE_RPC_Header h;
		h.Parse(msg, msg + len);
		if ( h.rpc_vers() == 5 && h.rpc_vers_minor() == 0 )
			{
			if ( h.frag_length() == len )
				return true;
			else
				{
				DEBUG_MSG("length mismatch: %d != %d\n",
					h.frag_length(), len);
				return false;
				}
			}
		}
	catch ( const binpac::Exception& )
		{
		// do nothing
		}

	return false;
	}

void DCE_RPC_Session::DeliverPDU(int is_orig, int len, const u_char* data)
	{
	if ( dce_rpc_message )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(is_orig, TYPE_BOOL));
		vl->append(new EnumVal(data[2], BifType::Enum::dce_rpc_ptype));
		vl->append(new StringVal(len, (const char*) data));

		analyzer->ConnectionEvent(dce_rpc_message, vl);
		}

	try
		{
		// TODO: handle incremental input
		binpac::DCE_RPC_Simple::DCE_RPC_PDU pdu;
		pdu.Parse(data, data + len);

		switch ( pdu.header()->PTYPE() ) {
		case binpac::DCE_RPC_Simple::DCE_RPC_BIND:
		case binpac::DCE_RPC_Simple::DCE_RPC_ALTER_CONTEXT:
			DeliverBind(&pdu);
			break;

		case binpac::DCE_RPC_Simple::DCE_RPC_REQUEST:
			DeliverRequest(&pdu);
			break;

		case binpac::DCE_RPC_Simple::DCE_RPC_RESPONSE:
			DeliverResponse(&pdu);
			break;
		}
		}
	catch ( const binpac::Exception& e )
		{
		analyzer->Weird(e.msg().c_str());
		}
	}

void DCE_RPC_Session::DeliverBind(const binpac::DCE_RPC_Simple::DCE_RPC_PDU* pdu)
	{
	binpac::DCE_RPC_Simple::DCE_RPC_Bind* bind = pdu->body()->bind();

	for ( int i = 0; i < bind->p_context_elem()->n_context_elem(); ++i )
		{
		binpac::DCE_RPC_Simple::p_cont_elem_t* elem =
			(*bind->p_context_elem()->p_cont_elem())[i];

		if_uuid = UUID(elem->abstract_syntax()->if_uuid().begin());
		uuid_map_t::const_iterator uuid_it =
			well_known_uuid_map().find(if_uuid);

		if ( uuid_it == well_known_uuid_map().end() )
			{
#ifdef DEBUG
			// conn->Weird(fmt("Unknown DCE_RPC interface %s",
			// 		if_uuid.to_string()));
#endif
			if_id = BifEnum::DCE_RPC_unknown_if;
			}
		else
			if_id = uuid_it->second;

		if ( dce_rpc_bind )
			{
			val_list* vl = new val_list;
			vl->append(analyzer->BuildConnVal());
			vl->append(new StringVal(if_uuid.to_string()));
			// vl->append(new EnumVal(if_id, BifType::Enum::dce_rpc_if_id));

			analyzer->ConnectionEvent(dce_rpc_bind, vl);
			}
		}
	}

void DCE_RPC_Session::DeliverRequest(const binpac::DCE_RPC_Simple::DCE_RPC_PDU* pdu)
	{
	binpac::DCE_RPC_Simple::DCE_RPC_Request* req = pdu->body()->request();

	opnum = req->opnum();

	if ( dce_rpc_request )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(opnum, TYPE_COUNT));
		vl->append(new StringVal(req->stub().length(),
			(const char*) req->stub().begin()));

		analyzer->ConnectionEvent(dce_rpc_request, vl);
		}

	switch ( if_id ) {
	case BifEnum::DCE_RPC_epmapper:
		DeliverEpmapperRequest(pdu, req);
		break;

	default:
		break;
	}
	}

void DCE_RPC_Session::DeliverResponse(const binpac::DCE_RPC_Simple::DCE_RPC_PDU* pdu)
	{
	binpac::DCE_RPC_Simple::DCE_RPC_Response* resp = pdu->body()->response();

	if ( dce_rpc_response )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(opnum, TYPE_COUNT));
		vl->append(new StringVal(resp->stub().length(),
			(const char*) resp->stub().begin()));
		analyzer->ConnectionEvent(dce_rpc_response, vl);
		}

	switch ( if_id ) {
	case BifEnum::DCE_RPC_epmapper:
		DeliverEpmapperResponse(pdu, resp);
		break;

	default:
		break;
	}
	}

void DCE_RPC_Session::DeliverEpmapperRequest(
	const binpac::DCE_RPC_Simple::DCE_RPC_PDU* /* pdu */,
	const binpac::DCE_RPC_Simple::DCE_RPC_Request* /* req */)
	{
	// DEBUG_MSG("Epmapper request opnum = %d\n", req->opnum());
	// ### TODO(rpang): generate an event on epmapper request
	}

void DCE_RPC_Session::DeliverEpmapperResponse(
	const binpac::DCE_RPC_Simple::DCE_RPC_PDU* pdu,
	const binpac::DCE_RPC_Simple::DCE_RPC_Response* resp)
	{
	// DEBUG_MSG("Epmapper request opnum = %d\n", req->opnum());
	switch ( opnum ) {
	case 3:	// Map
		DeliverEpmapperMapResponse(pdu, resp);
		break;
	}
	}


void DCE_RPC_Session::DeliverEpmapperMapResponse(
	const binpac::DCE_RPC_Simple::DCE_RPC_PDU* pdu,
	const binpac::DCE_RPC_Simple::DCE_RPC_Response* resp)
	{
	try
		{
		binpac::DCE_RPC_Simple::epmapper_map_resp epm_resp;

		epm_resp.Parse(resp->stub().begin(), resp->stub().end(),
				pdu->byteorder());

		for ( unsigned int twr_i = 0;
		      twr_i < epm_resp.towers()->actual_count(); ++twr_i )
			{
			binpac::DCE_RPC_Simple::epm_tower* twr =
				(*epm_resp.towers()->towers())[twr_i]->tower();

			mapped.addr = dce_rpc_endpoint_addr();
			mapped.uuid = UUID();

			for ( int floor_i = 0; floor_i < twr->num_floors();
			      ++floor_i )
				{
				binpac::DCE_RPC_Simple::epm_floor* floor =
						(*twr->floors())[floor_i];

				switch ( floor->protocol() ) {
				case binpac::DCE_RPC_Simple::EPM_PROTOCOL_UUID:
					if ( floor_i == 0 )
						mapped.uuid = UUID(floor->lhs()->data()->uuid()->if_uuid());
					break;

				case binpac::DCE_RPC_Simple::EPM_PROTOCOL_TCP:
					mapped.addr.port =
						floor->rhs()->data()->tcp();
					mapped.addr.proto = TRANSPORT_TCP;
					break;

				case binpac::DCE_RPC_Simple::EPM_PROTOCOL_UDP:
					mapped.addr.port =
						floor->rhs()->data()->udp();
					mapped.addr.proto = TRANSPORT_UDP;
					break;

				case binpac::DCE_RPC_Simple::EPM_PROTOCOL_IP:
					uint32 hostip = floor->rhs()->data()->ip();
					mapped.addr.addr = IPAddr(IPv4, &hostip, IPAddr::Host);
					break;
				}
				}

			if ( mapped.addr.is_valid_addr() )
				add_dce_rpc_endpoint(mapped.addr, mapped.uuid);

			if ( epm_map_response )
				{
				val_list* vl = new val_list;
				vl->append(analyzer->BuildConnVal());
				vl->append(new StringVal(mapped.uuid.to_string()));
				vl->append(new PortVal(mapped.addr.port, mapped.addr.proto));
				vl->append(new AddrVal(mapped.addr.addr));

				analyzer->ConnectionEvent(epm_map_response, vl);
				}
			}
		}
	catch ( const binpac::Exception& e )
		{
		analyzer->Weird(e.msg().c_str());
		}
	}

Contents_DCE_RPC_Analyzer::Contents_DCE_RPC_Analyzer(Connection* conn,
		bool orig, DCE_RPC_Session* arg_session, bool speculative)
: tcp::TCP_SupportAnalyzer("CONTENTS_DCE_RPC", conn, orig)
	{
	session = arg_session;
	msg_buf = 0;
	buf_len = 0;
	speculation = speculative ? 0 : 1;

	InitState();
	}

void Contents_DCE_RPC_Analyzer::InitState()
	{
	// Allocate space for header.
	if ( ! msg_buf )
		{
		buf_len = DCE_RPC_HEADER_LENGTH;
		msg_buf = new u_char[buf_len];
		}

	buf_n = 0;
	msg_len = 0;
	hdr = 0;
	}

Contents_DCE_RPC_Analyzer::~Contents_DCE_RPC_Analyzer()
	{
	delete [] msg_buf;
	delete hdr;
	}

void Contents_DCE_RPC_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	tcp::TCP_SupportAnalyzer::DeliverStream(len, data, orig);

	tcp::TCP_Analyzer* tcp =
		static_cast<tcp::TCP_ApplicationAnalyzer*>(Parent())->TCP();

	if ( tcp->HadGap(orig) || tcp->IsPartial() )
		return;

	if ( speculation == 0 ) // undecided
		{
		if ( ! DCE_RPC_Session::LooksLikeRPC(len, data) )
			speculation = -1;
		else
			speculation = 1;
		}

	if ( speculation < 0 )
		return;

	ASSERT(buf_len >= DCE_RPC_HEADER_LENGTH);
	while ( len > 0 )
		{
		if ( buf_n < DCE_RPC_HEADER_LENGTH )
			{
			while ( buf_n < DCE_RPC_HEADER_LENGTH && len > 0 )
				{
				msg_buf[buf_n] = *data;
				++buf_n; ++data; --len;
				}

			if ( buf_n < DCE_RPC_HEADER_LENGTH )
				break;
			else
				{
				if ( ! ParseHeader() )
					return;
				}
			}

		while ( buf_n < msg_len && len > 0 )
			{
			msg_buf[buf_n] = *data;
			++buf_n; ++data; --len;
			}

		if ( buf_n < msg_len )
			break;
		else
			{
			if ( msg_len > 0 )
				DeliverPDU(msg_len, msg_buf);
			// Reset for next message
			InitState();
			}
		}
	}

void Contents_DCE_RPC_Analyzer::DeliverPDU(int len, const u_char* data)
	{
	session->DeliverPDU(IsOrig(), len, data);
	}

bool Contents_DCE_RPC_Analyzer::ParseHeader()
	{
	delete hdr;
	hdr = 0;

	if ( msg_buf[0] != 5 )	// DCE/RPC version
		{
		Conn()->Weird("DCE/RPC_version_error (non-DCE/RPC?)");
		Conn()->SetSkip(1);
		msg_len = 0;
		return false;
		}

	hdr = new DCE_RPC_Header(this, msg_buf);

	msg_len = hdr->FragLen();
	if ( msg_len > buf_len )
		{
		u_char* new_msg_buf = new u_char[msg_len];
		memcpy(new_msg_buf, msg_buf, buf_n);
		delete [] msg_buf;
		buf_len = msg_len;
		msg_buf = new_msg_buf;
		hdr->SetBytes(new_msg_buf);
		}

	return true;
	}

DCE_RPC_Analyzer::DCE_RPC_Analyzer(Connection* conn, bool arg_speculative)
: tcp::TCP_ApplicationAnalyzer("DCE_RPC", conn)
	{
	session = new DCE_RPC_Session(this);
	speculative = arg_speculative;

	AddSupportAnalyzer(new Contents_DCE_RPC_Analyzer(conn, true, session,
								speculative));
	AddSupportAnalyzer(new Contents_DCE_RPC_Analyzer(conn, false, session,
								speculative));
	}

DCE_RPC_Analyzer::~DCE_RPC_Analyzer()
	{
	delete session;
	}
