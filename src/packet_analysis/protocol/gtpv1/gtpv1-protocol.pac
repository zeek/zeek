
type GTPv1_Header = record {
	flags:     uint8;
	msg_type:  uint8;
	length:    uint16;
	teid:      uint32;

	opt:       case has_opt of {
		true  -> opt_hdr: GTPv1_Opt_Header;
		false -> no_opt:  empty;
	};

	ext:       case e_flag of {
		true  -> ext_hdrs: GTPv1_Ext_Header[] &until($element.next_type == 0);
		false -> no_ext:   empty;
	};

	msg:       case msg_type of {
		16      -> create_pdp_ctx_request:  InformationElement[];
		17      -> create_pdp_ctx_response: InformationElement[];
		18      -> update_pdp_ctx_request:  InformationElement[];
		19      -> update_pdp_ctx_response: InformationElement[];
		20      -> delete_pdp_ctx_request:  InformationElement[];
		21      -> delete_pdp_ctx_response: InformationElement[];
		255     -> packet:  bytestring &restofdata;
		default -> unknown: bytestring &restofdata;
	};

} &let {
	version:  uint8 = (flags & 0xE0) >> 5;
	pt_flag:  bool  = flags & 0x10;
	rsv:      bool  = flags & 0x08;
	e_flag:   bool  = flags & 0x04;
	s_flag:   bool  = flags & 0x02;
	pn_flag:  bool  = flags & 0x01;
	has_opt:  bool  = flags & 0x07;
} &byteorder = bigendian, &exportsourcedata;

type GTPv1_Opt_Header = record {
	seq:       uint16;
	n_pdu:     uint8;
	next_type: uint8;
};

type GTPv1_Ext_Header = record {
	length:    uint8;
	contents:  bytestring &length=(length * 4 - 2);
	next_type: uint8;
};

enum InfoElementType {
	TYPE_CAUSE                       = 1,
	TYPE_IMSI                        = 2,
	TYPE_RAI                         = 3,
	TYPE_TLLI                        = 4,
	TYPE_P_TMSI                      = 5,
	TYPE_REORDER_REQ                 = 8,
	TYPE_AUTHN_TRIPLET               = 9,
	TYPE_MAP_CAUSE                   = 11,
	TYPE_P_TMSI_SIG                  = 12,
	TYPE_MS_VALID                    = 13,
	TYPE_RECOVERY                    = 14,
	TYPE_SELECTION_MODE              = 15,
	TYPE_TEID1                       = 16,
	TYPE_TEID_CONTROL_PLANE          = 17,
	TYPE_TEID2                       = 18,
	TYPE_TEARDOWN_IND                = 19,
	TYPE_NSAPI                       = 20,
	TYPE_RANAP_CAUSE                 = 21,
	TYPE_RAB_CTX                     = 22,
	TYPE_RADIO_PRIORITY_SMS          = 23,
	TYPE_RADIO_PRIORITY              = 24,
	TYPE_PACKET_FLOW_ID              = 25,
	TYPE_CHARGING_CHARACTERISTICS    = 26,
	TYPE_TRACE_REFERENCE             = 27,
	TYPE_TRACE_TYPE                  = 28,
	TYPE_MS_NOT_REACHABLE_REASON     = 29,
	TYPE_CHARGING_ID                 = 127,
	TYPE_END_USER_ADDR               = 128,
	TYPE_MM_CTX                      = 129,
	TYPE_PDP_CTX                     = 130,
	TYPE_ACCESS_POINT_NAME           = 131,
	TYPE_PROTO_CONFIG_OPTIONS        = 132,
	TYPE_GSN_ADDR                    = 133,
	TYPE_MSISDN                      = 134,
	TYPE_QOS_PROFILE                 = 135,
	TYPE_AUTHN_QUINTUPLET            = 136,
	TYPE_TRAFFIC_FLOW_TEMPLATE       = 137,
	TYPE_TARGET_ID                   = 138,
	TYPE_UTRAN_TRANSPARENT_CONTAINER = 139,
	TYPE_RAB_SETUP_INFO              = 140,
	TYPE_EXT_HEADER_TYPE_LIST        = 141,
	TYPE_TRIGGER_ID                  = 142,
	TYPE_OMC_ID                      = 143,
	TYPE_CHARGING_GATEWAY_ADDR       = 251,
	TYPE_PRIVATE_EXT                 = 255,
};

type InformationElement = record {
	type: uint8;

	len: case is_tlv of {
		true  -> tlv_len: uint16;
		false -> no_len:  empty;
	};

	value: case type of {
		TYPE_CAUSE -> cause: Cause;
		TYPE_IMSI -> imsi: IMSI;
		TYPE_RAI -> rai: RAI;
		TYPE_TLLI -> tlli: TLLI;
		TYPE_P_TMSI -> p_tmsi: P_TMSI;
		TYPE_REORDER_REQ -> reorder_req: ReorderReq;
		TYPE_AUTHN_TRIPLET -> authn_triplet: AuthN_Triplet;
		TYPE_MAP_CAUSE -> map_cause: MAP_Cause;
		TYPE_P_TMSI_SIG -> p_tmsi_sig: P_TMSI_Sig;
		TYPE_MS_VALID -> ms_valid: MS_Valid;
		TYPE_RECOVERY -> recovery: Recovery;
		TYPE_SELECTION_MODE -> selection_mode: SelectionMode;
		TYPE_TEID1 -> teid1: TEID1;
		TYPE_TEID_CONTROL_PLANE -> teidcp: TEID_ControlPlane;
		TYPE_TEID2 -> teid2: TEID2;
		TYPE_TEARDOWN_IND -> teardown_ind: TeardownInd;
		TYPE_NSAPI -> nsapi: NSAPI;
		TYPE_RANAP_CAUSE -> ranap_cause: RANAP_Cause;
		TYPE_RAB_CTX -> rab_ctx: RAB_Ctx;
		TYPE_RADIO_PRIORITY_SMS -> radio_priority_sms: RadioPrioritySMS;
		TYPE_RADIO_PRIORITY -> radio_priority: RadioPriority;
		TYPE_PACKET_FLOW_ID -> packet_flow_id: PacketFlowID;
		TYPE_CHARGING_CHARACTERISTICS -> charging_characteristics: ChargingCharacteristics;
		TYPE_TRACE_REFERENCE -> trace_reference: TraceReference;
		TYPE_TRACE_TYPE -> trace_type: TraceType;
		TYPE_MS_NOT_REACHABLE_REASON -> ms_not_reachable_reason: MS_Not_Reachable_Reason;
		TYPE_CHARGING_ID -> charging_id: ChargingID;
		TYPE_END_USER_ADDR -> end_user_addr: EndUserAddr(length);
		TYPE_MM_CTX -> mm_ctx: MM_Ctx(length);
		TYPE_PDP_CTX -> pdp_ctx: PDP_Ctx(length);
		TYPE_ACCESS_POINT_NAME -> ap_name: AP_Name(length);
		TYPE_PROTO_CONFIG_OPTIONS -> proto_config_opts: ProtoConfigOpts(length);
		TYPE_GSN_ADDR -> gsn_addr: GSN_Addr(length);
		TYPE_MSISDN -> msisdn: MSISDN(length);
		TYPE_QOS_PROFILE -> qos_profile: QoS_Profile(length);
		TYPE_AUTHN_QUINTUPLET -> authn_quintuplet: AuthN_Quintuplet(length);
		TYPE_TRAFFIC_FLOW_TEMPLATE -> traffic_flow_template: TrafficFlowTemplate(length);
		TYPE_TARGET_ID -> target_id: TargetID(length);
		TYPE_UTRAN_TRANSPARENT_CONTAINER -> utran_transparent_container: UTRAN_TransparentContainer(length);
		TYPE_RAB_SETUP_INFO -> rab_setup_info: RAB_SetupInfo(length);
		TYPE_EXT_HEADER_TYPE_LIST -> ext_hdr_type_list: ExtHdrTypeList(length);
		TYPE_TRIGGER_ID -> trigger_id: TriggerID(length);
		TYPE_OMC_ID -> omc_id: OMC_ID(length);
		TYPE_CHARGING_GATEWAY_ADDR -> charging_gateway_addr: ChargingGatewayAddr(length);
		TYPE_PRIVATE_EXT -> private_ext: PrivateExt(length);
		default -> unknown: bytestring &length=length;
	} &requires(length);

} &let {
	is_tlv: bool = (type & 0x80);
	length: uint16 = is_tlv ? tlv_len : Get_IE_Len(type);
};

type Cause = record {
	value: uint8;
};

function decode_imsi(v: uint8[8]): uint64
	%{
	uint64 rval = 0;
	uint8 digits[16];
	for ( size_t i = 0; i < v->size(); ++i )
		{
		digits[2 * i + 1] = ((*v)[i] & 0xf0) >> 4;
		digits[2 * i] = (*v)[i] & 0x0f;
		}
	int power = 0;
	for ( int i = 15; i >= 0; --i )
		{
		if ( digits[i] == 0x0f ) continue;
		rval += digits[i] * pow(10, power);
		++power;
		}
	return rval;
	%}

type IMSI = record {
	tbcd_encoded_value: uint8[8];
} &let {
	value: uint64 = decode_imsi(tbcd_encoded_value);
};

type RAI = record {
	mcc2_mcc1: uint8;
	mnc3_mcc3: uint8;
	mnc2_mnc1: uint8;
	lac: uint16;
	rac: uint8;
} &let {
	mcc1: uint8 = (mcc2_mcc1 & 0x0f);
	mcc2: uint8 = ((mcc2_mcc1 & 0xf0)>>4);
	mcc3: uint8 = (mnc3_mcc3 & 0x0f);
	mcc: uint16 = mcc1 * 100 + mcc2 * 10 + mcc3;
	mnc1: uint8 = (mnc2_mnc1 & 0x0f);
	mnc2: uint8 = ((mnc2_mnc1 & 0xf0)>>4);
	mnc3: uint8 = (mnc3_mcc3 & 0xf0)>>4;
	mnc: uint16 = (mnc3 & 0x0f) ? mnc1 * 10 + mnc2 : mnc1 * 100 + mnc2 * 10 + mnc3;
};

type TLLI = record {
	value: uint32;
};

type P_TMSI = record {
	value: uint32;
};

type ReorderReq = record {
	value: uint8;
} &let {
	req: bool = value & 0x01;
};

type AuthN_Triplet = record {
	rand: bytestring &length=16;
	sres: uint32;
	kc: uint64;
};

type MAP_Cause = record {
	value: uint8;
};

type P_TMSI_Sig = record {
	value: bytestring &length=3;
};

type MS_Valid = record {
	value: uint8;
};

type Recovery = record {
	restart_counter: uint8;
};

type SelectionMode = record {
	value: uint8;
} &let {
	mode: uint8 = value & 0x01;
};

type TEID1 = record {
	value: uint32;
};

type TEID_ControlPlane = record {
	value: uint32;
};

type TEID2 = record {
	spare_nsapi: uint8;
	teid2: uint32;
};

type TeardownInd = record {
	value: uint8;
} &let {
	ind: bool = value & 0x01;
};

type NSAPI = record {
	xxxx_nsapi: uint8;
} &let {
	nsapi: uint8 = xxxx_nsapi & 0x0f;
};

type RANAP_Cause = record {
	value: uint8;
};

type RAB_Ctx = record {
	spare_nsapi: uint8;
	dl_gtpu_seq_num: uint16;
	ul_gtpu_seq_num: uint16;
	dl_pdcp_seq_num: uint16;
	ul_pdcp_seq_num: uint16;
};

type RadioPrioritySMS = record {
	value: uint8;
};

type RadioPriority = record {
	nsapi_radio_priority: uint8;
};

type PacketFlowID = record {
	rsv_nsapi: uint8;
	packet_flow_id: uint8;
};

type ChargingCharacteristics = record {
	value: uint16;
};

type TraceReference = record {
	value: uint16;
};

type TraceType = record {
	value: uint16;
};

type MS_Not_Reachable_Reason = record {
	value: uint8;
};

type ChargingID = record {
	value: uint32;
};

type EndUserAddr(n: uint16) = record {
	spare_pdp_type_org: uint8;
	pdp_type_num: uint8;
	pdp_addr: bytestring &length=(n-2);
} &let {
	pdp_type_org: uint8 = spare_pdp_type_org & 0x0f;
};

type MM_Ctx(n: uint16) = record {
	spare_cksn_ksi: uint8;
	security_params: uint8;

	keys: case gsm_keys of {
		true  -> kc: uint64;
		false -> ck_ik: bytestring &length=32;
	};

	vector_len: case have_triplets of {
		true  -> no_quint_len: empty;
		false -> quint_len: uint16;
	};

	vectors: case have_triplets of {
		true  -> triplets: AuthN_Triplet[num_vectors];
		false -> quintuplets: AuthN_Quintuplet(quint_len)[num_vectors];
	} &requires(num_vectors);

	drx_param: uint16;
	ms_net_capability_len: uint8;
	ms_net_capability: bytestring &length=ms_net_capability_len;
	container_len: uint16;
	container: bytestring &length=container_len;

} &let {
	security_mode: uint8 = security_params >> 6;
	gsm_keys: bool = security_mode & 0x01;
	have_triplets: bool = (security_mode == 1);
	num_vectors: uint8 = (security_params & 0x38) >> 3;
};

type PDP_Ctx(n: uint16) = record {
	rsv_nsapi:	uint8;
	xxxx_sapi: uint8;
	qos_sub_len: uint8;
	qos_sub: QoS_Profile(qos_sub_len);
	qos_req_len: uint8;
	qos_req: QoS_Profile(qos_req_len);
	qos_neg_len: uint8;
	qos_neg: QoS_Profile(qos_neg_len);
	snd: uint16;
	snu: uint16;
	send_npdu_num: uint8;
	recv_npdu_num: uint8;
	ul_teid_cp: TEID_ControlPlane;
	ul_teid_data1: TEID1;
	pdp_ctx_id: uint8;
	spare_pdp_type_org: uint8;
	pdp_type_num: uint8;
	pdp_addr_len: uint8;
	pdp_addr: bytestring &length=pdp_addr_len;
	ggsn_addr_control_plane_len: uint8;
	ggsn_addr_control_plane: bytestring &length=ggsn_addr_control_plane_len;
	ggsn_addr_user_traffic_len: uint8;
	ggsn_addr_user_traffic: bytestring &length=ggsn_addr_user_traffic_len;
	apn_len: uint8;
	apn: AP_Name(apn_len);
	spare_transaction_id: uint8;
	transaction_id: uint8;
};

type AP_Name(n: uint16) = record {
	value: bytestring &length=n;
};

type ProtoConfigOpts(n: uint16) = record {
	value: bytestring &length=n;
};

type GSN_Addr(n: uint16) = record {
	value: bytestring &length=n;
};

type MSISDN(n: uint16) = record {
	value: bytestring &length=n;
};

type QoS_Profile(n: uint16) = record {
	alloc_retention_priority: uint8;
	data: bytestring &length=n-1;
};

type AuthN_Quintuplet(n: uint16) = record {
	rand: bytestring &length=16;
	xres_len: uint8;
	xres: bytestring &length=xres_len;
	ck: bytestring &length=16;
	ik: bytestring &length=16;
	autn_len: uint8;
	autn: bytestring &length=autn_len;
};

type TrafficFlowTemplate(n: uint16) = record {
	value: bytestring &length=n;
};

type TargetID(n: uint16) = record {
	value: bytestring &length=n;
};

type UTRAN_TransparentContainer(n: uint16) = record {
	value: bytestring &length=n;
};

type RAB_SetupInfo(n: uint16) = record {
	xxxx_nsapi: uint8;

	have_teid: case n of {
		1 -> no_teid: empty;
		default -> teid: TEID1;
	};

	have_addr: case n of {
		1 -> no_addr: empty;
		default -> rnc_addr: bytestring &length=n-5;
	};
};

type ExtHdrTypeList(n: uint16) = record {
	value: uint8[n];
};

type TriggerID(n: uint16) = record {
	value: bytestring &length=n;
};

type OMC_ID(n: uint16) = record {
	value: bytestring &length=n;
};

type ChargingGatewayAddr(n: uint16) = record {
	value: bytestring &length=n;
};

type PrivateExt(n: uint16) = record {
	id: uint16;
	value: bytestring &length=n-2;
};

function Get_IE_Len(t: uint8): uint16 =
	case t of {
	TYPE_CAUSE -> 1;
	TYPE_IMSI -> 8;
	TYPE_RAI -> 6;
	TYPE_TLLI -> 4;
	TYPE_P_TMSI -> 4;
	TYPE_REORDER_REQ -> 1;
	TYPE_AUTHN_TRIPLET -> 28;
	TYPE_MAP_CAUSE -> 1;
	TYPE_P_TMSI_SIG -> 3;
	TYPE_MS_VALID -> 1;
	TYPE_RECOVERY -> 1;
	TYPE_SELECTION_MODE -> 1;
	TYPE_TEID1 -> 4;
	TYPE_TEID_CONTROL_PLANE -> 4;
	TYPE_TEID2 -> 5;
	TYPE_TEARDOWN_IND -> 1;
	TYPE_NSAPI -> 1;
	TYPE_RANAP_CAUSE -> 1;
	TYPE_RAB_CTX -> 9;
	TYPE_RADIO_PRIORITY_SMS -> 1;
	TYPE_RADIO_PRIORITY -> 1;
	TYPE_PACKET_FLOW_ID -> 2;
	TYPE_CHARGING_CHARACTERISTICS -> 2;
	TYPE_TRACE_REFERENCE -> 2;
	TYPE_TRACE_TYPE -> 2;
	TYPE_MS_NOT_REACHABLE_REASON -> 1;
	TYPE_CHARGING_ID -> 4;
	};
