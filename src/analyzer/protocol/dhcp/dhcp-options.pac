
##############################
# SUBNET OPTION
##############################
let SUBNET_OPTION = 1;

# Parse the option
refine casetype OptionValue += {
	SUBNET_OPTION -> mask : uint32;
};

refine flow DHCP_Flow += {
	function process_subnet_option(v: OptionValue): bool
		%{
		${context.flow}->options->Assign(0, new AddrVal(htonl(${v.mask})));
		return true;
		%}
};

refine typeattr Option += &let {
	proc_subnet_option = $context.flow.process_subnet_option(info) &if(code==SUBNET_OPTION);
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
		${context.flow}->options->Assign(1, new StringVal(${v.host_name}.length(), (const char*) ${v.host_name}.begin()));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_host_name_option = $context.flow.process_host_name_option(info) &if(code==HOST_NAME_OPTION);
};


##############################
# REQ IP OPTION
##############################
let REQ_IP_OPTION = 50;

# Parse the option
refine casetype OptionValue += {
	REQ_IP_OPTION -> req_addr : uint32;
};

refine flow DHCP_Flow += {
	function process_req_ip_option(v: OptionValue): bool
		%{
		${context.flow}->options->Assign(2, new AddrVal(htonl(${v.req_addr})));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_req_ip_option = $context.flow.process_req_ip_option(info) &if(code==REQ_IP_OPTION);
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
		TableVal* router_list = new TableVal(BifType::Table::DHCP::RouterList);
		int num_routers = ${v.router_list}->size();
		vector<uint32>* rlist = ${v.router_list};

		for ( int i = 0; i < num_routers; ++i )
			{
			uint32 raddr = (*rlist)[i];
			::uint32 tmp_addr;
			tmp_addr = htonl(raddr);
			// index starting from 1
			Val* index = new Val(i + 1, TYPE_COUNT);
			router_list->Assign(index, new AddrVal(tmp_addr));
			Unref(index);
			}

		${context.flow}->options->Assign(3, router_list);

		return true;
		%}
};

refine typeattr Option += &let {
	proc_router_option = $context.flow.process_router_option(info) &if(code==ROUTER_OPTION);
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
		${context.flow}->options->Assign(4, new Val(lease, TYPE_INTERVAL));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_lease_option = $context.flow.process_lease_option(info) &if(code==LEASE_OPTION);
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
		${context.flow}->options->Assign(5, new AddrVal(htonl(${v.serv_addr})));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_serv_id_option = $context.flow.process_serv_id_option(info) &if(code==SERV_ID_OPTION);
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
		TableVal* params_list = new TableVal(BifType::Table::DHCP::ParamsList);
		int num_parms = ${v.par_req_list}->size();
		vector<uint8>* plist = ${v.par_req_list};
		
		for (int i=0; i < num_parms; ++i)
			{
			uint8 param = (*plist)[i];
			Val* index = new Val(i+1, TYPE_COUNT);
			params_list->Assign(index, new Val(param, TYPE_COUNT));
			Unref(index);
			}

		${context.flow}->options->Assign(6, params_list);

		return true;
		%}
};

refine typeattr Option += &let {
	proc_par_req_list_option = $context.flow.process_par_req_list_option(info) &if(code==PAR_REQ_LIST_OPTION);
};


##############################
# REN_TIME_OPTION OPTION
##############################
let REN_TIME_OPTION = 58;

# Parse the option
refine casetype OptionValue += {
	REN_TIME_OPTION -> ren_time : uint32;
};

refine flow DHCP_Flow += {
	function process_ren_time_option(v: OptionValue): bool
		%{
		double ren_time = static_cast<double>(${v.ren_time});
		${context.flow}->options->Assign(7, new Val(ren_time, TYPE_INTERVAL));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_ren_time_option = $context.flow.process_ren_time_option(info) &if(code==REN_TIME_OPTION);
};


##############################
# REB_TIME_OPTION OPTION
##############################
let REB_TIME_OPTION = 59;

# Parse the option
refine casetype OptionValue += {
	REB_TIME_OPTION -> reb_time : uint32;
};

refine flow DHCP_Flow += {
	function process_reb_time_option(v: OptionValue): bool
		%{
		double reb_time = static_cast<double>(${v.reb_time});
		${context.flow}->options->Assign(8, new Val(reb_time, TYPE_INTERVAL));

		return true;
		%}
};

refine typeattr Option += &let {
	proc_reb_time_option = $context.flow.process_reb_time_option(info) &if(code==REB_TIME_OPTION);
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
		client_id->Assign(0, new Val(${v.client_id.hwtype}, TYPE_COUNT));
		client_id->Assign(1, new StringVal(fmt_mac(${v.client_id.hwaddr}.begin(), ${v.client_id.hwaddr}.length())));

		${context.flow}->options->Assign(9, client_id);

		return true;
		%}
};

refine typeattr Option += &let {
	proc_client_id_option = $context.flow.process_client_id_option(info) &if(code==CLIENT_ID_OPTION);
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
	function process_relay_agent_inf_option(v: OptionValue): bool
		%{
		TableVal* relay_agent_sub_opt = new TableVal(BifType::Table::DHCP::SubOptList);
		RecordVal* r = new RecordVal(BifType::Record::DHCP::SubOpt);
		uint i = 1;
		for ( auto ptrsubopt = ${v.relay_agent_inf}->begin();
		      ptrsubopt != ${v.relay_agent_inf}->end(); ++ptrsubopt )
			{
			r = new RecordVal(BifType::Record::DHCP::SubOpt);
			r->Assign(0, new Val((*ptrsubopt)->code(), TYPE_COUNT));
			r->Assign(1, bytestring_to_val((*ptrsubopt)->value()));

			Val* index = new Val(i, TYPE_COUNT);
			relay_agent_sub_opt->Assign(index, r);
			Unref(index);
			++i;
			}

		${context.flow}->options->Assign(10, relay_agent_sub_opt);
		return true;
		%}
};

refine typeattr Option += &let {
	proc_relay_agent_info_option = $context.flow.process_relay_agent_inf_option(info) &if(code==RELAY_AGENT_INF_OPTION);
};



