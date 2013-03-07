
%code{
RecordVal* BuildGTPv1Hdr(const GTPv1_Header* pdu)
	{
	RecordVal* rv = new RecordVal(BifType::Record::gtpv1_hdr);

	rv->Assign(0, new Val(pdu->version(), TYPE_COUNT));
	rv->Assign(1, new Val(pdu->pt_flag(), TYPE_BOOL));
	rv->Assign(2, new Val(pdu->rsv(), TYPE_BOOL));
	rv->Assign(3, new Val(pdu->e_flag(), TYPE_BOOL));
	rv->Assign(4, new Val(pdu->s_flag(), TYPE_BOOL));
	rv->Assign(5, new Val(pdu->pn_flag(), TYPE_BOOL));
	rv->Assign(6, new Val(pdu->msg_type(), TYPE_COUNT));
	rv->Assign(7, new Val(pdu->length(), TYPE_COUNT));
	rv->Assign(8, new Val(pdu->teid(), TYPE_COUNT));

	if ( pdu->has_opt() )
		{
		rv->Assign(9, new Val(pdu->opt_hdr()->seq(), TYPE_COUNT));
		rv->Assign(10, new Val(pdu->opt_hdr()->n_pdu(), TYPE_COUNT));
		rv->Assign(11, new Val(pdu->opt_hdr()->next_type(), TYPE_COUNT));
		}

	return rv;
	}

Val* BuildIMSI(const InformationElement* ie)
	{
	return new Val(ie->imsi()->value(), TYPE_COUNT);
	}

Val* BuildRAI(const InformationElement* ie)
	{
	RecordVal* ev = new RecordVal(BifType::Record::gtp_rai);
	ev->Assign(0, new Val(ie->rai()->mcc(), TYPE_COUNT));
	ev->Assign(1, new Val(ie->rai()->mnc(), TYPE_COUNT));
	ev->Assign(2, new Val(ie->rai()->lac(), TYPE_COUNT));
	ev->Assign(3, new Val(ie->rai()->rac(), TYPE_COUNT));
	return ev;
	}

Val* BuildRecovery(const InformationElement* ie)
	{
	return new Val(ie->recovery()->restart_counter(), TYPE_COUNT);
	}

Val* BuildSelectionMode(const InformationElement* ie)
	{
	return new Val(ie->selection_mode()->mode(), TYPE_COUNT);
	}

Val* BuildTEID1(const InformationElement* ie)
	{
	return new Val(ie->teid1()->value(), TYPE_COUNT);
	}

Val* BuildTEID_ControlPlane(const InformationElement* ie)
	{
	return new Val(ie->teidcp()->value(), TYPE_COUNT);
	}

Val* BuildNSAPI(const InformationElement* ie)
	{
	return new Val(ie->nsapi()->nsapi(), TYPE_COUNT);
	}

Val* BuildChargingCharacteristics(const InformationElement* ie)
	{
	return new Val(ie->charging_characteristics()->value(), TYPE_COUNT);
	}

Val* BuildTraceReference(const InformationElement* ie)
	{
	return new Val(ie->trace_reference()->value(), TYPE_COUNT);
	}

Val* BuildTraceType(const InformationElement* ie)
	{
	return new Val(ie->trace_type()->value(), TYPE_COUNT);
	}

Val* BuildEndUserAddr(const InformationElement* ie)
	{
	RecordVal* ev = new RecordVal(BifType::Record::gtp_end_user_addr);
	ev->Assign(0, new Val(ie->end_user_addr()->pdp_type_org(), TYPE_COUNT));
	ev->Assign(1, new Val(ie->end_user_addr()->pdp_type_num(), TYPE_COUNT));

	int len = ie->end_user_addr()->pdp_addr().length();

	if ( len > 0 )
		{
		const uint8* d = ie->end_user_addr()->pdp_addr().data();

		switch ( ie->end_user_addr()->pdp_type_num() ) {
		case 0x21:
			ev->Assign(2, new AddrVal(
			  IPAddr(IPv4, (const uint32*) d, IPAddr::Network)));
			break;
		case 0x57:
			ev->Assign(2, new AddrVal(
			  IPAddr(IPv6, (const uint32*) d, IPAddr::Network)));
			break;
		default:
			ev->Assign(3, new StringVal(
			  new BroString((const u_char*) d, len, 0)));
			break;
		}
		}

	return ev;
	}

Val* BuildAccessPointName(const InformationElement* ie)
	{
	BroString* bs = new BroString((const u_char*) ie->ap_name()->value().data(),
	                              ie->ap_name()->value().length(), 0);
	return new StringVal(bs);
	}

Val* BuildProtoConfigOptions(const InformationElement* ie)
	{
	const u_char* d = (const u_char*) ie->proto_config_opts()->value().data();
	int len = ie->proto_config_opts()->value().length();
	return new StringVal(new BroString(d, len, 0));
	}

Val* BuildGSN_Addr(const InformationElement* ie)
	{
	RecordVal* ev = new RecordVal(BifType::Record::gtp_gsn_addr);

	int len = ie->gsn_addr()->value().length();
	const uint8* d = ie->gsn_addr()->value().data();

	if ( len == 4 )
		ev->Assign(0, new AddrVal(
		  IPAddr(IPv4, (const uint32*) d, IPAddr::Network)));
	else if ( len == 16 )
		ev->Assign(0, new AddrVal(
		  IPAddr(IPv6, (const uint32*) d, IPAddr::Network)));
	else
		ev->Assign(1, new StringVal(new BroString((const u_char*) d, len, 0)));

	return ev;
	}

Val* BuildMSISDN(const InformationElement* ie)
	{
	const u_char* d = (const u_char*) ie->msisdn()->value().data();
	int len = ie->msisdn()->value().length();
	return new StringVal(new BroString(d, len, 0));
	}

Val* BuildQoS_Profile(const InformationElement* ie)
	{
	RecordVal* ev = new RecordVal(BifType::Record::gtp_qos_profile);

	const u_char* d = (const u_char*) ie->qos_profile()->data().data();
	int len = ie->qos_profile()->data().length();

	ev->Assign(0, new Val(ie->qos_profile()->alloc_retention_priority(),
	                      TYPE_COUNT));
	ev->Assign(1, new StringVal(new BroString(d, len, 0)));

	return ev;
	}

Val* BuildTrafficFlowTemplate(const InformationElement* ie)
	{
	const uint8* d = ie->traffic_flow_template()->value().data();
	int len = ie->traffic_flow_template()->value().length();
	return new StringVal(new BroString((const u_char*) d, len, 0));
	}

Val* BuildTriggerID(const InformationElement* ie)
	{
	const uint8* d = ie->trigger_id()->value().data();
	int len = ie->trigger_id()->value().length();
	return new StringVal(new BroString((const u_char*) d, len, 0));
	}

Val* BuildOMC_ID(const InformationElement* ie)
	{
	const uint8* d = ie->omc_id()->value().data();
	int len = ie->omc_id()->value().length();
	return new StringVal(new BroString((const u_char*) d, len, 0));
	}

Val* BuildPrivateExt(const InformationElement* ie)
	{
	RecordVal* ev = new RecordVal(BifType::Record::gtp_private_extension);

	const uint8* d = ie->private_ext()->value().data();
	int len = ie->private_ext()->value().length();

	ev->Assign(0, new Val(ie->private_ext()->id(), TYPE_COUNT));
	ev->Assign(1, new StringVal(new BroString((const u_char*) d, len, 0)));

	return ev;
	}

Val* BuildCause(const InformationElement* ie)
	{
	return new Val(ie->cause()->value(), TYPE_COUNT);
	}

Val* BuildReorderReq(const InformationElement* ie)
	{
	return new Val(ie->reorder_req()->req(), TYPE_BOOL);
	}

Val* BuildChargingID(const InformationElement* ie)
	{
	return new Val(ie->charging_id()->value(), TYPE_COUNT);;
	}

Val* BuildChargingGatewayAddr(const InformationElement* ie)
	{
	const uint8* d = ie->charging_gateway_addr()->value().data();
	int len = ie->charging_gateway_addr()->value().length();
	if ( len == 4 )
		return new AddrVal(IPAddr(IPv4, (const uint32*) d, IPAddr::Network));
	else if ( len == 16 )
		return new AddrVal(IPAddr(IPv6, (const uint32*) d, IPAddr::Network));
	else
		return 0;
	}

Val* BuildTeardownInd(const InformationElement* ie)
	{
	return new Val(ie->teardown_ind()->ind(), TYPE_BOOL);
	}

void CreatePDP_Request(const BroAnalyzer& a, const GTPv1_Header* pdu)
	{
	if ( ! ::gtpv1_create_pdp_ctx_request ) return;

	RecordVal* rv = new RecordVal(
	  BifType::Record::gtp_create_pdp_ctx_request_elements);

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
			a->Weird(fmt("gtp_invalid_info_element_%d", (*v)[i]->type()));
			break;
		}
		}

	BifEvent::generate_gtpv1_create_pdp_ctx_request(a, a->Conn(),
	                                                BuildGTPv1Hdr(pdu), rv);
	}

void CreatePDP_Response(const BroAnalyzer& a, const GTPv1_Header* pdu)
	{
	if ( ! ::gtpv1_create_pdp_ctx_response )
	    return;

	RecordVal* rv = new RecordVal(
	  BifType::Record::gtp_create_pdp_ctx_response_elements);

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
			a->Weird(fmt("gtp_invalid_info_element_%d", (*v)[i]->type()));
			break;
		}
		}

	BifEvent::generate_gtpv1_create_pdp_ctx_response(a, a->Conn(),
	                                                 BuildGTPv1Hdr(pdu), rv);
	}

void UpdatePDP_Request(const BroAnalyzer& a, const GTPv1_Header* pdu)
	{
	if ( ! ::gtpv1_update_pdp_ctx_request )
	    return;

	RecordVal* rv = new RecordVal(
	  BifType::Record::gtp_update_pdp_ctx_request_elements);

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
			a->Weird(fmt("gtp_invalid_info_element_%d", (*v)[i]->type()));
			break;
		}
		}

	BifEvent::generate_gtpv1_update_pdp_ctx_request(a, a->Conn(),
	                                                BuildGTPv1Hdr(pdu), rv);
	}

void UpdatePDP_Response(const BroAnalyzer& a, const GTPv1_Header* pdu)
	{
	if ( ! ::gtpv1_update_pdp_ctx_response )
	    return;

	RecordVal* rv = new RecordVal(
	  BifType::Record::gtp_update_pdp_ctx_response_elements);

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
			a->Weird(fmt("gtp_invalid_info_element_%d", (*v)[i]->type()));
			break;
		}
		}

	BifEvent::generate_gtpv1_update_pdp_ctx_response(a, a->Conn(),
	                                                 BuildGTPv1Hdr(pdu), rv);
	}

void DeletePDP_Request(const BroAnalyzer& a, const GTPv1_Header* pdu)
	{
	if ( ! ::gtpv1_delete_pdp_ctx_request )
	    return;

	RecordVal* rv = new RecordVal(
	  BifType::Record::gtp_delete_pdp_ctx_request_elements);

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
			a->Weird(fmt("gtp_invalid_info_element_%d", (*v)[i]->type()));
			break;
		}
		}

	BifEvent::generate_gtpv1_delete_pdp_ctx_request(a, a->Conn(),
	                                                BuildGTPv1Hdr(pdu), rv);
	}

void DeletePDP_Response(const BroAnalyzer& a, const GTPv1_Header* pdu)
	{
	if ( ! ::gtpv1_delete_pdp_ctx_response )
	    return;

	RecordVal* rv = new RecordVal(
	  BifType::Record::gtp_delete_pdp_ctx_response_elements);

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
			a->Weird(fmt("gtp_invalid_info_element_%d", (*v)[i]->type()));
			break;
		}
		}

	BifEvent::generate_gtpv1_delete_pdp_ctx_response(a, a->Conn(),
	                                                 BuildGTPv1Hdr(pdu), rv);
	}
%}

connection GTPv1_Conn(bro_analyzer: BroAnalyzer)
	{
	upflow = GTPv1_Flow(true);
	downflow = GTPv1_Flow(false);

	%member{
		bool valid_orig;
		bool valid_resp;
	%}

	%init{
		valid_orig = valid_resp = false;
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
	}

flow GTPv1_Flow(is_orig: bool)
	{
	datagram = GTPv1_Header withcontext(connection, this);

	function violate(r: string, pdu: GTPv1_Header): void
		%{
		BroAnalyzer a = connection()->bro_analyzer();
		const_bytestring b = ${pdu.sourcedata};
		a->ProtocolViolation(r.c_str(), (const char*) b.begin(), b.length());
		%}

	function process_gtpv1(pdu: GTPv1_Header): bool
		%{
		BroAnalyzer a = connection()->bro_analyzer();
		Connection *c = a->Conn();
		const EncapsulationStack* e = c->GetEncapsulation();

		connection()->set_valid(is_orig(), false);

		if ( e && e->Depth() >= BifConst::Tunnel::max_depth )
			{
			reporter->Weird(c, "tunnel_depth");
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
			// Not interested in GTP'
			return false;
			}

		if ( ::gtpv1_message )
			BifEvent::generate_gtpv1_message(a, c, BuildGTPv1Hdr(pdu));

		switch ( ${pdu.msg_type} ) {
		case 16:
			CreatePDP_Request(a, pdu);
			return true;
		case 17:
			CreatePDP_Response(a, pdu);
			return true;
		case 18:
			UpdatePDP_Request(a, pdu);
			return true;
		case 19:
			UpdatePDP_Response(a, pdu);
			return true;
		case 20:
			DeletePDP_Request(a, pdu);
			return true;
		case 21:
			DeletePDP_Response(a, pdu);
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
		BroAnalyzer a = connection()->bro_analyzer();
		Connection *c = a->Conn();
		const EncapsulationStack* e = c->GetEncapsulation();

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

		IP_Hdr* inner = 0;
		int result = sessions->ParseIPPacket(${pdu.packet}.length(),
		     ${pdu.packet}.data(), ip->ip_v == 6 ? IPPROTO_IPV6 : IPPROTO_IPV4,
		     inner);

		if ( result == 0 )
			{
			connection()->set_valid(is_orig(), true);

			if ( (! BifConst::Tunnel::delay_gtp_confirmation) ||
			     (connection()->valid(true) && connection()->valid(false)) )
				a->ProtocolConfirmation();
			}

		else if ( result < 0 )
			violate("Truncated GTPv1", pdu);

		else
			violate("GTPv1 payload length", pdu);

		if ( result != 0 )
			{
			delete inner;
			return false;
			}

		if ( ::gtpv1_g_pdu_packet )
			BifEvent::generate_gtpv1_g_pdu_packet(a, c, BuildGTPv1Hdr(pdu),
			                                      inner->BuildPktHdrVal());

		EncapsulatingConn ec(c, BifEnum::Tunnel::GTPv1);

		sessions->DoNextInnerPacket(network_time(), 0, inner, e, ec);

		return true;
		%}
	};

refine typeattr GTPv1_Header += &let { proc_gtpv1 = $context.flow.process_gtpv1(this); };

