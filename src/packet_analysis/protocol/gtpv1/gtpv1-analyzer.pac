%extern{
#include "zeek/ZeekString.h"
#include "zeek/packet_analysis/protocol/gtpv1/GTPv1.h"
%}

%code{
zeek::RecordValPtr BuildGTPv1Hdr(const GTPv1_Header* pdu)
	{
	auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::gtpv1_hdr);

	rv->Assign(0, pdu->version());
	rv->Assign(1, pdu->pt_flag());
	rv->Assign(2, pdu->rsv());
	rv->Assign(3, pdu->e_flag());
	rv->Assign(4, pdu->s_flag());
	rv->Assign(5, pdu->pn_flag());
	rv->Assign(6, pdu->msg_type());
	rv->Assign(7, pdu->length());
	rv->Assign(8, pdu->teid());

	if ( pdu->has_opt() )
		{
		rv->Assign(9, pdu->opt_hdr()->seq());
		rv->Assign(10, pdu->opt_hdr()->n_pdu());
		rv->Assign(11, pdu->opt_hdr()->next_type());
		}

	return rv;
	}

static zeek::ValPtr BuildIMSI(const InformationElement* ie)
	{
	return zeek::val_mgr->Count(ie->imsi()->value());
	}

static zeek::ValPtr BuildRAI(const InformationElement* ie)
	{
	auto ev = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::gtp_rai);
	ev->Assign(0, ie->rai()->mcc());
	ev->Assign(1, ie->rai()->mnc());
	ev->Assign(2, ie->rai()->lac());
	ev->Assign(3, ie->rai()->rac());
	return ev;
	}

static zeek::ValPtr BuildRecovery(const InformationElement* ie)
	{
	return zeek::val_mgr->Count(ie->recovery()->restart_counter());
	}

static zeek::ValPtr BuildSelectionMode(const InformationElement* ie)
	{
	return zeek::val_mgr->Count(ie->selection_mode()->mode());
	}

static zeek::ValPtr BuildTEID1(const InformationElement* ie)
	{
	return zeek::val_mgr->Count(ie->teid1()->value());
	}

static zeek::ValPtr BuildTEID_ControlPlane(const InformationElement* ie)
	{
	return zeek::val_mgr->Count(ie->teidcp()->value());
	}

static zeek::ValPtr BuildNSAPI(const InformationElement* ie)
	{
	return zeek::val_mgr->Count(ie->nsapi()->nsapi());
	}

static zeek::ValPtr BuildChargingCharacteristics(const InformationElement* ie)
	{
	return zeek::val_mgr->Count(ie->charging_characteristics()->value());
	}

static zeek::ValPtr BuildTraceReference(const InformationElement* ie)
	{
	return zeek::val_mgr->Count(ie->trace_reference()->value());
	}

static zeek::ValPtr BuildTraceType(const InformationElement* ie)
	{
	return zeek::val_mgr->Count(ie->trace_type()->value());
	}

zeek::ValPtr BuildEndUserAddr(const InformationElement* ie)
	{
	auto ev = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::gtp_end_user_addr);
	ev->Assign(0, ie->end_user_addr()->pdp_type_org());
	ev->Assign(1, ie->end_user_addr()->pdp_type_num());

	int len = ie->end_user_addr()->pdp_addr().length();

	if ( len > 0 )
		{
		const uint8* d = ie->end_user_addr()->pdp_addr().data();

		switch ( ie->end_user_addr()->pdp_type_num() ) {
		case 0x21:
			ev->Assign(2, zeek::make_intrusive<zeek::AddrVal>(
			  zeek::IPAddr(IPv4, (const uint32*) d, zeek::IPAddr::Network)));
			break;
		case 0x57:
			ev->Assign(2, zeek::make_intrusive<zeek::AddrVal>(
			  zeek::IPAddr(IPv6, (const uint32*) d, zeek::IPAddr::Network)));
			break;
		default:
			ev->Assign(3, new zeek::String((const u_char*) d, len, false));
			break;
		}
		}

	return ev;
	}

zeek::ValPtr BuildAccessPointName(const InformationElement* ie)
	{
	zeek::String* bs = new zeek::String((const u_char*) ie->ap_name()->value().data(),
	                                          ie->ap_name()->value().length(), false);
	return zeek::make_intrusive<zeek::StringVal>(bs);
	}

zeek::ValPtr BuildProtoConfigOptions(const InformationElement* ie)
	{
	const u_char* d = (const u_char*) ie->proto_config_opts()->value().data();
	int len = ie->proto_config_opts()->value().length();
	return zeek::make_intrusive<zeek::StringVal>(new zeek::String(d, len, false));
	}

zeek::ValPtr BuildGSN_Addr(const InformationElement* ie)
	{
	auto ev = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::gtp_gsn_addr);

	int len = ie->gsn_addr()->value().length();
	const uint8* d = ie->gsn_addr()->value().data();

	if ( len == 4 )
		ev->Assign(0, zeek::make_intrusive<zeek::AddrVal>(
		  zeek::IPAddr(IPv4, (const uint32*) d, zeek::IPAddr::Network)));
	else if ( len == 16 )
		ev->Assign(0, zeek::make_intrusive<zeek::AddrVal>(
		  zeek::IPAddr(IPv6, (const uint32*) d, zeek::IPAddr::Network)));
	else
		ev->Assign(1, new zeek::String((const u_char*) d, len, false));

	return ev;
	}

zeek::ValPtr BuildMSISDN(const InformationElement* ie)
	{
	const u_char* d = (const u_char*) ie->msisdn()->value().data();
	int len = ie->msisdn()->value().length();
	return zeek::make_intrusive<zeek::StringVal>(new zeek::String(d, len, false));
	}

zeek::ValPtr BuildQoS_Profile(const InformationElement* ie)
	{
	auto ev = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::gtp_qos_profile);

	const u_char* d = (const u_char*) ie->qos_profile()->data().data();
	int len = ie->qos_profile()->data().length();

	ev->Assign(0, ie->qos_profile()->alloc_retention_priority());
	ev->Assign(1, new zeek::String(d, len, false));

	return ev;
	}

zeek::ValPtr BuildTrafficFlowTemplate(const InformationElement* ie)
	{
	const uint8* d = ie->traffic_flow_template()->value().data();
	int len = ie->traffic_flow_template()->value().length();
	return zeek::make_intrusive<zeek::StringVal>(new zeek::String((const u_char*) d, len, false));
	}

zeek::ValPtr BuildTriggerID(const InformationElement* ie)
	{
	const uint8* d = ie->trigger_id()->value().data();
	int len = ie->trigger_id()->value().length();
	return zeek::make_intrusive<zeek::StringVal>(new zeek::String((const u_char*) d, len, false));
	}

zeek::ValPtr BuildOMC_ID(const InformationElement* ie)
	{
	const uint8* d = ie->omc_id()->value().data();
	int len = ie->omc_id()->value().length();
	return zeek::make_intrusive<zeek::StringVal>(new zeek::String((const u_char*) d, len, false));
	}

zeek::ValPtr BuildPrivateExt(const InformationElement* ie)
	{
	auto ev = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::gtp_private_extension);

	const uint8* d = ie->private_ext()->value().data();
	int len = ie->private_ext()->value().length();

	ev->Assign(0, ie->private_ext()->id());
	ev->Assign(1, new zeek::String((const u_char*) d, len, false));

	return ev;
	}

static zeek::ValPtr BuildCause(const InformationElement* ie)
	{
	return zeek::val_mgr->Count(ie->cause()->value());
	}

static zeek::ValPtr BuildReorderReq(const InformationElement* ie)
	{
	return zeek::val_mgr->Bool(ie->reorder_req()->req());
	}

static zeek::ValPtr BuildChargingID(const InformationElement* ie)
	{
	return zeek::val_mgr->Count(ie->charging_id()->value());;
	}

zeek::ValPtr BuildChargingGatewayAddr(const InformationElement* ie)
	{
	const uint8* d = ie->charging_gateway_addr()->value().data();
	int len = ie->charging_gateway_addr()->value().length();
	if ( len == 4 )
		return zeek::make_intrusive<zeek::AddrVal>(zeek::IPAddr(IPv4, (const uint32*) d, zeek::IPAddr::Network));
	else if ( len == 16 )
		return zeek::make_intrusive<zeek::AddrVal>(zeek::IPAddr(IPv6, (const uint32*) d, zeek::IPAddr::Network));
	else
		return nullptr;
	}

static zeek::ValPtr BuildTeardownInd(const InformationElement* ie)
	{
	return zeek::val_mgr->Bool(ie->teardown_ind()->ind());
	}

void CreatePDP_Request(const ZeekPacketAnalyzer& a, zeek::Connection* c, const GTPv1_Header* pdu)
	{
	if ( ! ::gtpv1_create_pdp_ctx_request ) return;

	auto rv = zeek::make_intrusive<zeek::RecordVal>(
	  zeek::BifType::Record::gtp_create_pdp_ctx_request_elements);

	const vector<InformationElement *> * v = pdu->create_pdp_ctx_request();

	bool second_nsapi = false;
	bool second_gsn_addr = false;

	for ( size_t i = 0; i < v->size(); ++i )
		{
		const InformationElement* ie = (*v)[i];

		switch ( ie->type() ) {
		case GTPv1::TYPE_IMSI:
			rv->Assign(0, BuildIMSI(ie));
			break;
		case GTPv1::TYPE_RAI:
			rv->Assign(1, BuildRAI(ie));
			break;
		case GTPv1::TYPE_RECOVERY:
			rv->Assign(2, BuildRecovery(ie));
			break;
		case GTPv1::TYPE_SELECTION_MODE:
			rv->Assign(3, BuildSelectionMode(ie));
			break;
		case GTPv1::TYPE_TEID1:
			rv->Assign(4, BuildTEID1(ie));
			break;
		case GTPv1::TYPE_TEID_CONTROL_PLANE:
			rv->Assign(5, BuildTEID_ControlPlane(ie));
			break;
		case GTPv1::TYPE_NSAPI:
			if ( second_nsapi )
				rv->Assign(7, BuildNSAPI(ie));
			else
				{
				second_nsapi = true;
				rv->Assign(6, BuildNSAPI(ie));
				}
			break;
		case GTPv1::TYPE_CHARGING_CHARACTERISTICS:
			rv->Assign(8, BuildChargingCharacteristics(ie));
			break;
		case GTPv1::TYPE_TRACE_REFERENCE:
			rv->Assign(9, BuildTraceReference(ie));
			break;
		case GTPv1::TYPE_TRACE_TYPE:
			rv->Assign(10, BuildTraceType(ie));
			break;
		case GTPv1::TYPE_END_USER_ADDR:
			rv->Assign(11, BuildEndUserAddr(ie));
			break;
		case GTPv1::TYPE_ACCESS_POINT_NAME:
			rv->Assign(12, BuildAccessPointName(ie));
			break;
		case GTPv1::TYPE_PROTO_CONFIG_OPTIONS:
			rv->Assign(13, BuildProtoConfigOptions(ie));
			break;
		case GTPv1::TYPE_GSN_ADDR:
			if ( second_gsn_addr )
				rv->Assign(15, BuildGSN_Addr(ie));
			else
				{
				second_gsn_addr = true;
				rv->Assign(14, BuildGSN_Addr(ie));
				}
			break;
		case GTPv1::TYPE_MSISDN:
			rv->Assign(16, BuildMSISDN(ie));
			break;
		case GTPv1::TYPE_QOS_PROFILE:
			rv->Assign(17, BuildQoS_Profile(ie));
			break;
		case GTPv1::TYPE_TRAFFIC_FLOW_TEMPLATE:
			rv->Assign(18, BuildTrafficFlowTemplate(ie));
			break;
		case GTPv1::TYPE_TRIGGER_ID:
			rv->Assign(19, BuildTriggerID(ie));
			break;
		case GTPv1::TYPE_OMC_ID:
			rv->Assign(20, BuildOMC_ID(ie));
			break;
		case GTPv1::TYPE_PRIVATE_EXT:
			rv->Assign(21, BuildPrivateExt(ie));
			break;
		default:
			a->Weird("gtp_invalid_info_element", nullptr, zeek::util::fmt("%d", (*v)[i]->type()));
			break;
		}
		}

	zeek::BifEvent::enqueue_gtpv1_create_pdp_ctx_request(nullptr, c, BuildGTPv1Hdr(pdu), std::move(rv));
	}

void CreatePDP_Response(const ZeekPacketAnalyzer& a, zeek::Connection* c, const GTPv1_Header* pdu)
	{
	if ( ! ::gtpv1_create_pdp_ctx_response )
	    return;

	auto rv = zeek::make_intrusive<zeek::RecordVal>(
	  zeek::BifType::Record::gtp_create_pdp_ctx_response_elements);

	const vector<InformationElement *> * v = pdu->create_pdp_ctx_response();

	bool second_gsn_addr = false;

	for ( size_t i = 0; i < v->size(); ++i )
		{
		const InformationElement* ie = (*v)[i];

		switch ( ie->type() ) {
		case GTPv1::TYPE_CAUSE:
			rv->Assign(0, BuildCause(ie));
			break;
		case GTPv1::TYPE_REORDER_REQ:
			rv->Assign(1, BuildReorderReq(ie));
			break;
		case GTPv1::TYPE_RECOVERY:
			rv->Assign(2, BuildRecovery(ie));
			break;
		case GTPv1::TYPE_TEID1:
			rv->Assign(3, BuildTEID1(ie));
			break;
		case GTPv1::TYPE_TEID_CONTROL_PLANE:
			rv->Assign(4, BuildTEID_ControlPlane(ie));
			break;
		case GTPv1::TYPE_CHARGING_ID:
			rv->Assign(5, BuildChargingID(ie));
			break;
		case GTPv1::TYPE_END_USER_ADDR:
			rv->Assign(6, BuildEndUserAddr(ie));
			break;
		case GTPv1::TYPE_PROTO_CONFIG_OPTIONS:
			rv->Assign(7, BuildProtoConfigOptions(ie));
			break;
		case GTPv1::TYPE_GSN_ADDR:
			if ( second_gsn_addr )
				rv->Assign(9, BuildGSN_Addr(ie));
			else
				{
				second_gsn_addr = true;
				rv->Assign(8, BuildGSN_Addr(ie));
				}
			break;
		case GTPv1::TYPE_QOS_PROFILE:
			rv->Assign(10, BuildQoS_Profile(ie));
			break;
		case GTPv1::TYPE_CHARGING_GATEWAY_ADDR:
			rv->Assign(11, BuildChargingGatewayAddr(ie));
			break;
		case GTPv1::TYPE_PRIVATE_EXT:
			rv->Assign(12, BuildPrivateExt(ie));
			break;
		default:
			a->Weird("gtp_invalid_info_element", nullptr, zeek::util::fmt("%d", (*v)[i]->type()));
			break;
		}
		}

	zeek::BifEvent::enqueue_gtpv1_create_pdp_ctx_response(nullptr, c, BuildGTPv1Hdr(pdu), std::move(rv));
	}

void UpdatePDP_Request(const ZeekPacketAnalyzer& a, zeek::Connection* c, const GTPv1_Header* pdu)
	{
	if ( ! ::gtpv1_update_pdp_ctx_request )
	    return;

	auto rv = zeek::make_intrusive<zeek::RecordVal>(
	  zeek::BifType::Record::gtp_update_pdp_ctx_request_elements);

	const vector<InformationElement *> * v = pdu->update_pdp_ctx_request();

	bool second_gsn_addr = false;

	for ( size_t i = 0; i < v->size(); ++i )
		{
		const InformationElement* ie = (*v)[i];

		switch ( ie->type() ) {
		case GTPv1::TYPE_IMSI:
			rv->Assign(0, BuildIMSI(ie));
			break;
		case GTPv1::TYPE_RAI:
			rv->Assign(1, BuildRAI(ie));
			break;
		case GTPv1::TYPE_RECOVERY:
			rv->Assign(2, BuildRecovery(ie));
			break;
		case GTPv1::TYPE_TEID1:
			rv->Assign(3, BuildTEID1(ie));
			break;
		case GTPv1::TYPE_TEID_CONTROL_PLANE:
			rv->Assign(4, BuildTEID_ControlPlane(ie));
			break;
		case GTPv1::TYPE_NSAPI:
			rv->Assign(5, BuildNSAPI(ie));
			break;
		case GTPv1::TYPE_TRACE_REFERENCE:
			rv->Assign(6, BuildTraceReference(ie));
			break;
		case GTPv1::TYPE_TRACE_TYPE:
			rv->Assign(7, BuildTraceType(ie));
			break;
		case GTPv1::TYPE_GSN_ADDR:
			if ( second_gsn_addr )
				rv->Assign(9, BuildGSN_Addr(ie));
			else
				{
				second_gsn_addr = true;
				rv->Assign(8, BuildGSN_Addr(ie));
				}
			break;
		case GTPv1::TYPE_QOS_PROFILE:
			rv->Assign(10, BuildQoS_Profile(ie));
			break;
		case GTPv1::TYPE_TRAFFIC_FLOW_TEMPLATE:
			rv->Assign(11, BuildTrafficFlowTemplate(ie));
			break;
		case GTPv1::TYPE_TRIGGER_ID:
			rv->Assign(12, BuildTriggerID(ie));
			break;
		case GTPv1::TYPE_OMC_ID:
			rv->Assign(13, BuildOMC_ID(ie));
			break;
		case GTPv1::TYPE_PRIVATE_EXT:
			rv->Assign(14, BuildPrivateExt(ie));
			break;
		case GTPv1::TYPE_END_USER_ADDR:
			rv->Assign(15, BuildEndUserAddr(ie));
			break;
		default:
			a->Weird("gtp_invalid_info_element", nullptr, zeek::util::fmt("%d", (*v)[i]->type()));
			break;
		}
		}

	zeek::BifEvent::enqueue_gtpv1_update_pdp_ctx_request(nullptr, c, BuildGTPv1Hdr(pdu), std::move(rv));
	}

void UpdatePDP_Response(const ZeekPacketAnalyzer& a, zeek::Connection* c, const GTPv1_Header* pdu)
	{
	if ( ! ::gtpv1_update_pdp_ctx_response )
	    return;

	auto rv = zeek::make_intrusive<zeek::RecordVal>(
	  zeek::BifType::Record::gtp_update_pdp_ctx_response_elements);

	const vector<InformationElement *> * v = pdu->update_pdp_ctx_response();

	bool second_gsn_addr = false;

	for ( size_t i = 0; i < v->size(); ++i )
		{
		const InformationElement* ie = (*v)[i];

		switch ( ie->type() ) {
		case GTPv1::TYPE_CAUSE:
			rv->Assign(0, BuildCause(ie));
			break;
		case GTPv1::TYPE_RECOVERY:
			rv->Assign(1, BuildRecovery(ie));
			break;
		case GTPv1::TYPE_TEID1:
			rv->Assign(2, BuildTEID1(ie));
			break;
		case GTPv1::TYPE_TEID_CONTROL_PLANE:
			rv->Assign(3, BuildTEID_ControlPlane(ie));
			break;
		case GTPv1::TYPE_CHARGING_ID:
			rv->Assign(4, BuildChargingID(ie));
			break;
		case GTPv1::TYPE_GSN_ADDR:
			if ( second_gsn_addr )
				rv->Assign(6, BuildGSN_Addr(ie));
			else
				{
				second_gsn_addr = true;
				rv->Assign(5, BuildGSN_Addr(ie));
				}
			break;
		case GTPv1::TYPE_QOS_PROFILE:
			rv->Assign(7, BuildQoS_Profile(ie));
			break;
		case GTPv1::TYPE_CHARGING_GATEWAY_ADDR:
			rv->Assign(8, BuildChargingGatewayAddr(ie));
			break;
		case GTPv1::TYPE_PRIVATE_EXT:
			rv->Assign(9, BuildPrivateExt(ie));
			break;
		default:
			a->Weird("gtp_invalid_info_element", nullptr, zeek::util::fmt("%d", (*v)[i]->type()));
			break;
		}
		}

	zeek::BifEvent::enqueue_gtpv1_update_pdp_ctx_response(nullptr, c, BuildGTPv1Hdr(pdu), std::move(rv));
	}

void DeletePDP_Request(const ZeekPacketAnalyzer& a, zeek::Connection* c, const GTPv1_Header* pdu)
	{
	if ( ! ::gtpv1_delete_pdp_ctx_request )
	    return;

	auto rv = zeek::make_intrusive<zeek::RecordVal>(
	  zeek::BifType::Record::gtp_delete_pdp_ctx_request_elements);

	const vector<InformationElement *> * v = pdu->delete_pdp_ctx_request();

	for ( size_t i = 0; i < v->size(); ++i )
		{
		const InformationElement* ie = (*v)[i];

		switch ( ie->type() ) {
		case GTPv1::TYPE_TEARDOWN_IND:
			rv->Assign(0, BuildTeardownInd(ie));
			break;
		case GTPv1::TYPE_NSAPI:
			rv->Assign(1, BuildNSAPI(ie));
			break;
		case GTPv1::TYPE_PRIVATE_EXT:
			rv->Assign(2, BuildPrivateExt(ie));
			break;
		default:
			a->Weird("gtp_invalid_info_element", nullptr, zeek::util::fmt("%d", (*v)[i]->type()));
			break;
		}
		}

	zeek::BifEvent::enqueue_gtpv1_delete_pdp_ctx_request(nullptr, c, BuildGTPv1Hdr(pdu), std::move(rv));
	}

void DeletePDP_Response(const ZeekPacketAnalyzer& a, zeek::Connection* c, const GTPv1_Header* pdu)
	{
	if ( ! ::gtpv1_delete_pdp_ctx_response )
	    return;

	auto rv = zeek::make_intrusive<zeek::RecordVal>(
	  zeek::BifType::Record::gtp_delete_pdp_ctx_response_elements);

	const vector<InformationElement *> * v = pdu->delete_pdp_ctx_response();

	for ( size_t i = 0; i < v->size(); ++i )
		{
		const InformationElement* ie = (*v)[i];

		switch ( ie->type() ) {
		case GTPv1::TYPE_CAUSE:
			rv->Assign(0, BuildCause(ie));
			break;
		case GTPv1::TYPE_PRIVATE_EXT:
			rv->Assign(1, BuildPrivateExt(ie));
			break;
		default:
			a->Weird("gtp_invalid_info_element", nullptr, zeek::util::fmt("%d", (*v)[i]->type()));
			break;
		}
		}

	zeek::BifEvent::enqueue_gtpv1_delete_pdp_ctx_response(nullptr, c, BuildGTPv1Hdr(pdu), std::move(rv));
	}
%}

connection GTPv1_Conn(zeek_analyzer: ZeekPacketAnalyzer)
	{
	upflow = GTPv1_Flow(true);
	downflow = GTPv1_Flow(false);

	%member{
		bool valid_orig;
		bool valid_resp;
		ZeekPacket* packet;
	%}

	%init{
		valid_orig = false;
		valid_resp = false;
		packet = nullptr;
	%}

	function valid(orig: bool): bool
		%{
		return orig ? valid_orig : valid_resp;
		%}

	function set_valid(orig: bool, val: bool): void
		%{
		if ( orig )
			valid_orig = val;
		else
			valid_resp = val;
		%}

	function set_raw_packet(p: ZeekPacket): void
		%{
		packet = p;
		%}

	function get_raw_packet(): ZeekPacket
		%{
		return packet;
		%}
	}

flow GTPv1_Flow(is_orig: bool)
	{
	datagram = GTPv1_Header withcontext(connection, this);

	function violate(r: string, pdu: GTPv1_Header): void
		%{
		ZeekPacketAnalyzer a = connection()->zeek_analyzer();
		ZeekPacket* p = connection()->get_raw_packet();
		a->AnalyzerViolation(r.c_str(), p->session);
		%}

	function process_gtpv1(pdu: GTPv1_Header): bool
		%{
		ZeekPacketAnalyzer a = connection()->zeek_analyzer();
		ZeekPacket* p = connection()->get_raw_packet();
		zeek::Connection* c = static_cast<zeek::Connection*>(p->session);
		const std::shared_ptr<zeek::EncapsulationStack> e = p->encap;

		connection()->set_valid(is_orig(), false);

		if ( e && e->Depth() >= zeek::BifConst::Tunnel::max_depth )
			{
			a->Weird("tunnel_depth");
			return false;
			}

		if ( e && e->LastType() == BifEnum::Tunnel::GTPv1 )
			{
			// GTP is never tunneled in GTP so, this must be a regular packet
			violate("GTP-in-GTP", pdu);
			return false;
			}

		if ( ${pdu.version} != 1 )
			{
			// Only know of GTPv1 with Version == 1
			violate("GTPv1 bad Version", pdu);
			return false;
			}

		if ( ! ${pdu.pt_flag} )
			{
			// Not interested in GTP
			return false;
			}

		if ( ::gtpv1_message )
			zeek::BifEvent::enqueue_gtpv1_message(nullptr, c, BuildGTPv1Hdr(pdu));

		switch ( ${pdu.msg_type} ) {
		case 16:
			CreatePDP_Request(a, c, pdu);
			return true;
		case 17:
			CreatePDP_Response(a, c, pdu);
			return true;
		case 18:
			UpdatePDP_Request(a, c, pdu);
			return true;
		case 19:
			UpdatePDP_Response(a, c, pdu);
			return true;
		case 20:
			DeletePDP_Request(a, c, pdu);
			return true;
		case 21:
			DeletePDP_Response(a, c, pdu);
			return true;
		case 255:
			return process_g_pdu(pdu);
		default:
			return false;
		}

		return false;
		%}

	function process_g_pdu(pdu: GTPv1_Header): bool
		%{
		ZeekPacketAnalyzer a = connection()->zeek_analyzer();
		ZeekPacket* p = connection()->get_raw_packet();
		zeek::Connection* c = static_cast<zeek::Connection*>(p->session);

		if ( ${pdu.packet}.length() < (int)sizeof(struct ip) )
			{
			violate("Truncated GTPv1", pdu);
			return false;
			}

		const struct ip* ip = (const struct ip*) ${pdu.packet}.data();

		if ( ip->ip_v != 4 && ip->ip_v != 6 )
			{
			violate("non-IP packet in GTPv1", pdu);
			return false;
			}

		int hdr_len = 8;

		if ( pdu->has_opt() )
			hdr_len += 4;

		if ( pdu->e_flag() && pdu->ext_hdrs() )
			for ( const auto& eh : *pdu->ext_hdrs() )
				hdr_len += 2 + eh->contents().length();

		auto next_hdr = ip->ip_v == 6 ? IPPROTO_IPV6 : IPPROTO_IPV4;
		zeek::RecordValPtr hdr_val;

		if ( ::gtpv1_g_pdu_packet )
			hdr_val = BuildGTPv1Hdr(pdu);

		static_cast<zeek::packet_analysis::gtpv1::GTPv1_Analyzer*>(a)->SetInnerInfo(
			hdr_len, next_hdr, std::move(hdr_val));

		return true;
		%}
	};

refine typeattr GTPv1_Header += &let { proc_gtpv1 = $context.flow.process_gtpv1(this); };
