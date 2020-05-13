##############################
# SUBNET OPTION
##############################
let SUBNET_OPTION = 1;

# Parse the option
refine casetype OptionValue += {
	SUBNET_OPTION -> subnet : uint32;
};

refine flow DHCP_Flow += {
	function process_subnet_option(v: OptionValue): bool
		%{
		${context.flow}->options->Assign(1, make_intrusive<AddrVal>(htonl(${v.subnet})));
		return true;
		%}
};

refine typeattr Option += &let {
	proc_subnet_option = $context.flow.process_subnet_option(info.value) &if(code==SUBNET_OPTION);
};


##############################
# TIME OFFSET OPTION
##############################
let TIME_OFFSET_OPTION = 2;

# Parse the option
refine casetype OptionValue += {
	TIME_OFFSET_OPTION -> time_offset : int32;
};

refine flow DHCP_Flow += {
	function process_time_offset_option(v: OptionValue): bool
		%{
		${context.flow}->options->Assign(25, val_mgr->Int(${v.time_offset}));
		return true;
		%}
};

refine typeattr Option += &let {
	proc_timeoffset_option = $context.flow.process_time_offset_option(info.value) &if(code==TIME_OFFSET_OPTION);
};


##############################
# ROUTER OPTION
##############################
let ROUTER_OPTION = 3;

# Parse the option
refine casetype OptionValue += {
	ROUTER_OPTION -> router_list : uint32[length/4];
};

refine flow DHCP_Flow += {
	function process_router_option(v: OptionValue): bool
		%{
		auto router_list = make_intrusive<VectorVal>(IntrusivePtr{NewRef{}, BifType::Vector::DHCP::Addrs});
		int num_routers = ${v.router_list}->size();
		vector<uint32>* rlist = ${v.router_list};

		for ( int i = 0; i < num_routers; ++i )
			{
			uint32 raddr = (*rlist)[i];
			router_list->Assign(i, make_intrusive<AddrVal>(htonl(raddr)));
			}

		${context.flow}->options->Assign(2, std::move(router_list));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_router_option = $context.flow.process_router_option(info.value) &if(code==ROUTER_OPTION);
};


##############################
# TIME SERVER OPTION
##############################
let TIME_SERVER_OPTION = 4;

# Parse the option
refine casetype OptionValue += {
	TIME_SERVER_OPTION -> timeserver_list : uint32[length/4];
};

refine flow DHCP_Flow += {
	function process_timeserver_option(v: OptionValue): bool
		%{
		auto timeserver_list = make_intrusive<VectorVal>(IntrusivePtr{NewRef{}, BifType::Vector::DHCP::Addrs});
		int num_servers = ${v.timeserver_list}->size();
		vector<uint32>* rlist = ${v.timeserver_list};

		for ( int i = 0; i < num_servers; ++i )
			{
			uint32 raddr = (*rlist)[i];
			timeserver_list->Assign(i, make_intrusive<AddrVal>(htonl(raddr)));
			}

		${context.flow}->options->Assign(26, std::move(timeserver_list));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_timeserver_option = $context.flow.process_timeserver_option(info.value) &if(code==TIME_SERVER_OPTION);
};


##############################
# NAME SERVER OPTION
##############################
let NAME_SERVER_OPTION = 5;

# Parse the option
refine casetype OptionValue += {
	NAME_SERVER_OPTION -> nameserver_list : uint32[length/4];
};

refine flow DHCP_Flow += {
	function process_nameserver_option(v: OptionValue): bool
		%{
		auto nameserver_list = make_intrusive<VectorVal>(IntrusivePtr{NewRef{}, BifType::Vector::DHCP::Addrs});
		int num_servers = ${v.nameserver_list}->size();
		vector<uint32>* rlist = ${v.nameserver_list};

		for ( int i = 0; i < num_servers; ++i )
			{
			uint32 raddr = (*rlist)[i];
			nameserver_list->Assign(i, make_intrusive<AddrVal>(htonl(raddr)));
			}

		${context.flow}->options->Assign(27, std::move(nameserver_list));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_nameserver_option = $context.flow.process_nameserver_option(info.value) &if(code==NAME_SERVER_OPTION);
};


##############################
# DNS SERVER OPTION
##############################
let DNS_SERVER_OPTION = 6;

# Parse the option
refine casetype OptionValue += {
	DNS_SERVER_OPTION -> dns_server_list : uint32[length/4];
};

refine flow DHCP_Flow += {
	function process_dns_server_option(v: OptionValue): bool
		%{
		auto server_list = make_intrusive<VectorVal>(IntrusivePtr{NewRef{}, BifType::Vector::DHCP::Addrs});
		int num_servers = ${v.dns_server_list}->size();
		vector<uint32>* rlist = ${v.dns_server_list};

		for ( int i = 0; i < num_servers; ++i )
			{
			uint32 raddr = (*rlist)[i];
			server_list->Assign(i, make_intrusive<AddrVal>(htonl(raddr)));
			}

		${context.flow}->options->Assign(3, std::move(server_list));
		return true;
		%}
};

refine typeattr Option += &let {
	proc_dns_server_option = $context.flow.process_dns_server_option(info.value) &if(code==DNS_SERVER_OPTION);
};


##############################
# HOST NAME OPTION
##############################
let HOST_NAME_OPTION = 12;

# Parse the option
refine casetype OptionValue += {
	HOST_NAME_OPTION -> host_name : bytestring &length=length;
};

refine flow DHCP_Flow += {
	function process_host_name_option(v: OptionValue): bool
		%{
		${context.flow}->options->Assign(4, make_intrusive<StringVal>(${v.host_name}.length(),
		                                                  reinterpret_cast<const char*>(${v.host_name}.begin())));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_host_name_option = $context.flow.process_host_name_option(info.value) &if(code==HOST_NAME_OPTION);
};


##############################
# DOMAIN NAME OPTION
##############################
let DOMAIN_NAME_OPTION = 15;

# Parse the option
refine casetype OptionValue += {
	DOMAIN_NAME_OPTION -> domain_name : bytestring &length=length;
};

refine flow DHCP_Flow += {
	function process_domain_name_option(v: OptionValue): bool
		%{
		int last_non_null = 0;

		for ( int i = 0; i < ${v.domain_name}.length(); ++i )
			{
			if ( *(${v.domain_name}.begin() + i ) != 0 )
				last_non_null = i;
			}

		${context.flow}->options->Assign(5, make_intrusive<StringVal>(last_non_null == 0 ? 0 : last_non_null + 1,
		                                                  reinterpret_cast<const char*>(${v.domain_name}.begin())));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_domain_name_option = $context.flow.process_domain_name_option(info.value) &if(code==DOMAIN_NAME_OPTION);
};


##############################
# FORWARDING OPTION
##############################
let FORWARDING_OPTION = 19;

# Parse the option
refine casetype OptionValue += {
	FORWARDING_OPTION -> forwarding : uint8;
};

refine flow DHCP_Flow += {
	function process_forwarding_option(v: OptionValue): bool
		%{
		${context.flow}->options->Assign(6, val_mgr->Bool(${v.forwarding} == 0 ? false : true));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_forwarding_option = $context.flow.process_forwarding_option(info.value) &if(code==FORWARDING_OPTION);
};


##############################
# BROADCAST ADDRESS OPTION
##############################
let BROADCAST_ADDRESS_OPTION = 28;

# Parse the option
refine casetype OptionValue += {
	BROADCAST_ADDRESS_OPTION -> broadcast_address : uint32;
};

refine flow DHCP_Flow += {
	function process_broadcast_address_option(v: OptionValue): bool
		%{
		${context.flow}->options->Assign(7, make_intrusive<AddrVal>(htonl(${v.broadcast_address})));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_broadcast_address_option = $context.flow.process_broadcast_address_option(info.value) &if(code==BROADCAST_ADDRESS_OPTION);
};


##############################
# NTP SERVER OPTION
##############################
let NTP_SERVER_OPTION = 42;

# Parse the option
refine casetype OptionValue += {
	NTP_SERVER_OPTION -> ntpserver_list : uint32[length/4];
};

refine flow DHCP_Flow += {
	function process_ntpserver_option(v: OptionValue): bool
		%{
		auto ntpserver_list = make_intrusive<VectorVal>(IntrusivePtr{NewRef{}, BifType::Vector::DHCP::Addrs});
		int num_servers = ${v.ntpserver_list}->size();
		vector<uint32>* rlist = ${v.ntpserver_list};

		for ( int i = 0; i < num_servers; ++i )
			{
			uint32 raddr = (*rlist)[i];
			ntpserver_list->Assign(i, make_intrusive<AddrVal>(htonl(raddr)));
			}

		${context.flow}->options->Assign(28, std::move(ntpserver_list));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_ntpserver_option = $context.flow.process_ntpserver_option(info.value) &if(code==NTP_SERVER_OPTION);
};

##############################
# VENDOR SPECIFIC OPTION
##############################
let VENDOR_SPECIFIC_OPTION = 43;

# Parse the option
refine casetype OptionValue += {
	VENDOR_SPECIFIC_OPTION -> vendor_specific : bytestring &length=length;
};

refine flow DHCP_Flow += {
	function process_vendor_specific_option(v: OptionValue): bool
		%{
		${context.flow}->options->Assign(8, make_intrusive<StringVal>(${v.vendor_specific}.length(),
		                                                  reinterpret_cast<const char*>(${v.vendor_specific}.begin())));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_vendor_specific_option = $context.flow.process_vendor_specific_option(info.value) &if(code==VENDOR_SPECIFIC_OPTION);
};


##############################
# NETBIOS NAME SERVER OPTION
##############################
let NBNS_OPTION = 44;

# Parse the option
refine casetype OptionValue += {
	NBNS_OPTION -> nbns : uint32[length/4];
};

refine flow DHCP_Flow += {
	function process_nbns_option(v: OptionValue): bool
		%{
		auto server_list = make_intrusive<VectorVal>(IntrusivePtr{NewRef{}, BifType::Vector::DHCP::Addrs});
		int num_servers = ${v.nbns}->size();
		vector<uint32>* rlist = ${v.nbns};

		for ( int i = 0; i < num_servers; ++i )
			{
			uint32 raddr = (*rlist)[i];
			server_list->Assign(i, make_intrusive<AddrVal>(htonl(raddr)));
			}

		${context.flow}->options->Assign(9, std::move(server_list));
		return true;
		%}
};

refine typeattr Option += &let {
	proc_nbns_option = $context.flow.process_nbns_option(info.value) &if(code==NBNS_OPTION);
};


##############################
# ADDR REQUEST OPTION
##############################
let ADDR_REQUEST_OPTION = 50;

# Parse the option
refine casetype OptionValue += {
	ADDR_REQUEST_OPTION -> addr_request : uint32;
};

refine flow DHCP_Flow += {
	function process_addr_request_option(v: OptionValue): bool
		%{
		${context.flow}->options->Assign(10, make_intrusive<AddrVal>(htonl(${v.addr_request})));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_addr_request_option = $context.flow.process_addr_request_option(info.value) &if(code==ADDR_REQUEST_OPTION);
};


##############################
# LEASE_OPTION OPTION
##############################
let LEASE_OPTION = 51;

# Parse the option
refine casetype OptionValue += {
	LEASE_OPTION -> lease : uint32;
};

refine flow DHCP_Flow += {
	function process_lease_option(v: OptionValue): bool
		%{
		double lease = static_cast<double>(${v.lease});
		${context.flow}->options->Assign(11, make_intrusive<Val>(lease, TYPE_INTERVAL));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_lease_option = $context.flow.process_lease_option(info.value) &if(code==LEASE_OPTION);
};


##############################
# SERV_ID_OPTION OPTION
##############################
let SERV_ID_OPTION = 54;

# Parse the option
refine casetype OptionValue += {
	SERV_ID_OPTION -> serv_addr : uint32;
};

refine flow DHCP_Flow += {
	function process_serv_id_option(v: OptionValue): bool
		%{
		${context.flow}->options->Assign(12, make_intrusive<AddrVal>(htonl(${v.serv_addr})));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_serv_id_option = $context.flow.process_serv_id_option(info.value) &if(code==SERV_ID_OPTION);
};


##############################
# PAR_REQ_LIST OPTION
##############################
let PAR_REQ_LIST_OPTION = 55;

# Parse the option
refine casetype OptionValue += {
	PAR_REQ_LIST_OPTION -> par_req_list : uint8[length];
};

refine flow DHCP_Flow += {
	function process_par_req_list_option(v: OptionValue): bool
		%{
		auto params = make_intrusive<VectorVal>(zeek::id::index_vec);
		int num_parms = ${v.par_req_list}->size();
		vector<uint8>* plist = ${v.par_req_list};

		for ( int i = 0; i < num_parms; ++i )
			{
			uint8 param = (*plist)[i];
			params->Assign(i, val_mgr->Count(param));
			}

		${context.flow}->options->Assign(13, std::move(params));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_par_req_list_option = $context.flow.process_par_req_list_option(info.value) &if(code==PAR_REQ_LIST_OPTION);
};


##############################
# MESSAGE OPTION
##############################
let MESSAGE_OPTION = 56;

# Parse the option
refine casetype OptionValue += {
	MESSAGE_OPTION -> message : bytestring &length=length;
};

refine flow DHCP_Flow += {
	function process_message_option(v: OptionValue): bool
		%{
		${context.flow}->options->Assign(14, make_intrusive<StringVal>(${v.message}.length(), 
		                                                   reinterpret_cast<const char*>(${v.message}.begin())));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_message_option = $context.flow.process_message_option(info.value) &if(code==MESSAGE_OPTION);
};


##############################
# MAX MESSAGE SIZE OPTION
##############################
let MAX_MESSAGE_SIZE_OPTION = 57;

# Parse the option
refine casetype OptionValue += {
	MAX_MESSAGE_SIZE_OPTION -> max_msg_size : uint16;
};

refine flow DHCP_Flow += {
	function process_max_message_size_option(v: OptionValue): bool
		%{
		${context.flow}->options->Assign(15, val_mgr->Count(${v.max_msg_size}));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_max_message_size_option = $context.flow.process_max_message_size_option(info.value) &if(code==MAX_MESSAGE_SIZE_OPTION);
};


##############################
# RENEWAL_TIME_OPTION OPTION
##############################
let RENEWAL_TIME_OPTION = 58;

# Parse the option
refine casetype OptionValue += {
	RENEWAL_TIME_OPTION -> renewal_time : uint32;
};

refine flow DHCP_Flow += {
	function process_renewal_time_option(v: OptionValue): bool
		%{
		double renewal_time = static_cast<double>(${v.renewal_time});
		${context.flow}->options->Assign(16, make_intrusive<Val>(renewal_time, TYPE_INTERVAL));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_renewal_time_option = $context.flow.process_renewal_time_option(info.value) &if(code==RENEWAL_TIME_OPTION);
};


##############################
# REBINDING_TIME_OPTION OPTION
##############################
let REBINDING_TIME_OPTION = 59;

# Parse the option
refine casetype OptionValue += {
	REBINDING_TIME_OPTION -> rebinding_time : uint32;
};

refine flow DHCP_Flow += {
	function process_rebinding_time_option(v: OptionValue): bool
		%{
		double rebinding_time = static_cast<double>(${v.rebinding_time});
		${context.flow}->options->Assign(17, make_intrusive<Val>(rebinding_time, TYPE_INTERVAL));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_rebinding_time_option = $context.flow.process_rebinding_time_option(info.value) &if(code==REBINDING_TIME_OPTION);
};


##############################
# VENDOR CLASS OPTION
##############################
let VENDOR_CLASS_OPTION = 60;

# Parse the option
refine casetype OptionValue += {
	VENDOR_CLASS_OPTION -> vendor_class : bytestring &length=length;
};

refine flow DHCP_Flow += {
	function process_vendor_class_option(v: OptionValue): bool
		%{
		${context.flow}->options->Assign(18, make_intrusive<StringVal>(${v.vendor_class}.length(),
		                                                   reinterpret_cast<const char*>(${v.vendor_class}.begin())));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_vendor_class_option = $context.flow.process_vendor_class_option(info.value) &if(code==VENDOR_CLASS_OPTION);
};


##############################
# CLIENT_ID_OPTION OPTION
##############################
let CLIENT_ID_OPTION = 61;

type Client_Identifier(length: uint8) = record {
	hwtype : uint8;
	hwaddr : bytestring &length = length - 1;
};

# Parse the option
refine casetype OptionValue += {
	CLIENT_ID_OPTION -> client_id : Client_Identifier(length);
};

refine flow DHCP_Flow += {
	function process_client_id_option(v: OptionValue): bool
		%{
		RecordVal* client_id = new RecordVal(BifType::Record::DHCP::ClientID);
		client_id->Assign(0, val_mgr->Count(${v.client_id.hwtype}));
		client_id->Assign(1, make_intrusive<StringVal>(fmt_mac(${v.client_id.hwaddr}.begin(), ${v.client_id.hwaddr}.length())));

		${context.flow}->options->Assign(19, client_id);

		return true;
		%}
};

refine typeattr Option += &let {
	proc_client_id_option = $context.flow.process_client_id_option(info.value) &if(code==CLIENT_ID_OPTION);
};


##############################
# USER CLASS OPTION
##############################
let USER_CLASS_OPTION = 77;

# Parse the option
refine casetype OptionValue += {
	USER_CLASS_OPTION -> user_class : bytestring &length=length;
};

refine flow DHCP_Flow += {
	function process_user_class_option(v: OptionValue): bool
		%{
		${context.flow}->options->Assign(20, make_intrusive<StringVal>(${v.user_class}.length(),
		                                                   reinterpret_cast<const char*>(${v.user_class}.begin())));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_user_class_option = $context.flow.process_user_class_option(info.value) &if(code==USER_CLASS_OPTION);
};


##############################
# CLIENT FQDN OPTION
##############################
let CLIENT_FQDN_OPTION = 81;

type Client_FQDN(length: uint8) = record {
	flags       : uint8;
	rcode1      : uint8;
	rcode2      : uint8;
	domain_name : bytestring &length=length-3;
};

# Parse the option
refine casetype OptionValue += {
	CLIENT_FQDN_OPTION -> client_fqdn : Client_FQDN(length);
};

refine flow DHCP_Flow += {
	function process_client_fqdn_option(v: OptionValue): bool
		%{
		RecordVal* client_fqdn = new RecordVal(BifType::Record::DHCP::ClientFQDN);
		client_fqdn->Assign(0, val_mgr->Count(${v.client_fqdn.flags}));
		client_fqdn->Assign(1, val_mgr->Count(${v.client_fqdn.rcode1}));
		client_fqdn->Assign(2, val_mgr->Count(${v.client_fqdn.rcode2}));
		const char* domain_name = reinterpret_cast<const char*>(${v.client_fqdn.domain_name}.begin());
		client_fqdn->Assign(3, make_intrusive<StringVal>(${v.client_fqdn.domain_name}.length(), domain_name));

		${context.flow}->options->Assign(21, client_fqdn);

		return true;
		%}
};

refine typeattr Option += &let {
	proc_client_fqdn_option = $context.flow.process_client_fqdn_option(info.value) &if(code==CLIENT_FQDN_OPTION);
};


##############################
# RELAY_AGENT_INF OPTION
##############################
let RELAY_AGENT_INF_OPTION = 82;

type Relay_Agent_SubOption(tot_len: uint8) = record {
	code   : uint8;
	length : uint8;
	value  : bytestring &length = length;
} &let {
	sum_len: uint8 = $context.flow.get_dhcp_sumlen(length + 2);
	last: bool = (sum_len == tot_len);
};

# Parse the option
refine casetype OptionValue += {
	RELAY_AGENT_INF_OPTION -> relay_agent_inf : Relay_Agent_SubOption(length)[] &until($element.last);
};

refine flow DHCP_Flow += {
	%member{
		uint8 sum_len;
	%}

	%init{
		sum_len = 0;
	%}

	%cleanup{
		sum_len = 0;
	%}

	function get_dhcp_sumlen(len: uint8): uint8
		%{
		sum_len = len + sum_len;
		return sum_len;
		%}

	function process_relay_agent_inf_option(v: OptionValue): bool
		%{
		auto relay_agent_sub_opt = make_intrusive<VectorVal>(IntrusivePtr{NewRef{}, BifType::Vector::DHCP::SubOpts});

		uint16 i = 0;

		for ( auto ptrsubopt = ${v.relay_agent_inf}->begin();
		      ptrsubopt != ${v.relay_agent_inf}->end(); ++ptrsubopt )
			{
			auto r = new RecordVal(BifType::Record::DHCP::SubOpt);
			r->Assign(0, val_mgr->Count((*ptrsubopt)->code()));
			r->Assign(1, to_stringval((*ptrsubopt)->value()));

			relay_agent_sub_opt->Assign(i, r);
			++i;
			}

		${context.flow}->options->Assign(22, std::move(relay_agent_sub_opt));
		return true;
		%}
};

refine typeattr Option += &let {
	proc_relay_agent_info_option = $context.flow.process_relay_agent_inf_option(info.value) &if(code==RELAY_AGENT_INF_OPTION);
};


##############################
# AUTO_CONFIG OPTION
##############################
let AUTO_CONFIG_OPTION = 116;

# Parse the option
refine casetype OptionValue += {
	AUTO_CONFIG_OPTION -> auto_config : uint8;
};

refine flow DHCP_Flow += {
	function process_auto_config_option(v: OptionValue): bool
		%{
		${context.flow}->options->Assign(23, val_mgr->Bool(${v.auto_config} == 0 ? false : true));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_auto_config_option = $context.flow.process_auto_config_option(info.value) &if(code==AUTO_CONFIG_OPTION);
};


##############################
# AUTO PROXY CONFIG OPTION
##############################
let AUTO_PROXY_CONFIG_OPTION = 252;

# Parse the option
refine casetype OptionValue += {
	AUTO_PROXY_CONFIG_OPTION -> auto_proxy_config : bytestring &length=length;
};

refine flow DHCP_Flow += {
	function process_auto_proxy_config_option(v: OptionValue): bool
		%{
		int string_len = ${v.auto_proxy_config}.length();

		if ( string_len == 0 )
			{
			${context.flow}->options->Assign(24, make_intrusive<StringVal>(0, ""));
			return true;
			}


		const char* last_char = reinterpret_cast<const char*>(${v.auto_proxy_config}.begin() + string_len - 1);

		bool has_newline = *last_char == '\x0a';

		if ( has_newline )
			--string_len;

		${context.flow}->options->Assign(24, make_intrusive<StringVal>(string_len,
		                                                   reinterpret_cast<const char*>(${v.auto_proxy_config}.begin())));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_auto_proxy_config_option = $context.flow.process_auto_proxy_config_option(info.value) &if(code==AUTO_PROXY_CONFIG_OPTION);
};


