# $Id:$

%include portmap-protocol.pac

# Add a function to the hook in the RPC connection to build the call Val.
refine casefunc RPC_BuildCallVal += {
	RPC_SERVICE_PORTMAP ->
		PortmapBuildCallVal(call, call.params.portmap);
};

# ... and a function invocation to handle successful portmap replies.
refine typeattr PortmapResults += &let {
	action_reply: bool = $context.connection.ProcessPortmapReply(this);
};

# ... and a function to handle failed portmap calls.
refine casefunc RPC_CallFailed += {
	RPC_SERVICE_PORTMAP	-> PortmapCallFailed(connection, call, status);
};

# Build portmap call Val.
function PortmapBuildCallVal(call: RPC_Call, params: PortmapParams): BroVal =
	case call.proc of {
		PMAPPROC_NULL, PMAPPROC_DUMP
			-> NULL;
		PMAPPROC_SET, PMAPPROC_UNSET
			-> PortmapBuildMappingVal(params.mapping);
		PMAPPROC_GETPORT
			-> PortmapBuildPortRequest(params.mapping);
		PMAPPROC_CALLIT
			-> PortmapBuildCallItVal(params.callit);
	};

function PortmapBuildPortVal(port: uint32, proto: uint32): BroPortVal
	%{
	// TODO: replace port with CheckPort(port)
	return new PortVal(port, proto == IPPROTO_TCP ?
					TRANSPORT_TCP : TRANSPORT_UDP);
	%}

function PortmapBuildMappingVal(params: PortmapMapping): BroVal
	%{
	RecordVal* mapping = new RecordVal(pm_mapping);

	mapping->Assign(0, new Val(params->prog(), TYPE_COUNT));
	mapping->Assign(1, new Val(params->vers(), TYPE_COUNT));
	mapping->Assign(2, PortmapBuildPortVal(params->port(),
	                                       params->proto()));

	return mapping;
	%}

function PortmapBuildPortRequest(params: PortmapMapping): BroVal
	%{
	RecordVal* request = new RecordVal(pm_port_request);

	request->Assign(0, new Val(params->prog(), TYPE_COUNT));
	request->Assign(1, new Val(params->vers(), TYPE_COUNT));
	request->Assign(2, new Val(params->proto() == IPPROTO_TCP, TYPE_BOOL));

	return request;
	%}

function PortmapBuildCallItVal(params: PortmapCallItParams): BroVal
	%{
	RecordVal* c = new RecordVal(pm_callit_request);

	c->Assign(0, new Val(params->prog(), TYPE_COUNT));
	c->Assign(1, new Val(params->vers(), TYPE_COUNT));
	c->Assign(2, new Val(params->proc(), TYPE_COUNT));
	c->Assign(3, new Val(params->params()->length(), TYPE_COUNT));

	return c;
	%}

function PortmapBuildDumpVal(params: PortmapDumpResults): BroVal
	%{
	TableVal* mappings = new TableVal(pm_mappings);

	for ( int i = 0; i < params->size(); ++i )
		{
		Val* m = PortmapBuildMappingVal((*params)[i]->mapping());
		Val* index = new Val(i + 1, TYPE_COUNT);
		mappings->Assign(index, m);
		Unref(index);
		}

	return mappings;
	%}

refine connection RPC_Conn += {
	function ProcessPortmapReply(results: PortmapResults): bool
		%{
		RPC_Call const* call = results->call();
		PortmapParams const* params = call->params()->portmap();

		switch ( call->proc() ) {
		case PMAPPROC_NULL:
			bro_event_pm_request_null(bro_analyzer(), bro_analyzer()->Conn());
			break;

		case PMAPPROC_SET:
			bro_event_pm_request_set(bro_analyzer(),
				bro_analyzer()->Conn(),
				call->call_val(), results->set());
			break;

		case PMAPPROC_UNSET:
			bro_event_pm_request_unset(bro_analyzer(),
				bro_analyzer()->Conn(),
				call->call_val(), results->unset());
			break;

		case PMAPPROC_GETPORT:
			bro_event_pm_request_getport(bro_analyzer(),
				bro_analyzer()->Conn(),
				call->call_val(),
				PortmapBuildPortVal(results->getport(),
					params->mapping()->proto()));
			break;

		case PMAPPROC_DUMP:
			bro_event_pm_request_dump(bro_analyzer(),
				bro_analyzer()->Conn(),
				PortmapBuildDumpVal(results->dump()));
			break;

		case PMAPPROC_CALLIT:
			bro_event_pm_request_callit(bro_analyzer(),
				bro_analyzer()->Conn(),
				call->call_val(),
				new PortVal(results->callit()->port(),
					    TRANSPORT_UDP));
			break;

		default:
			return false;
		}

		return true;
		%}
};

function PortmapCallFailed(connection: RPC_Conn,
			call: RPC_Call,
			status: EnumRPCStatus): bool
	%{
	// BroEnum::rpc_status st = static_cast<BroEnum::rpc_status>(status);
	BroEnum::rpc_status st = (BroEnum::rpc_status) status;

	switch ( call->proc() ) {
	case PMAPPROC_NULL:
		bro_event_pm_attempt_null(connection->bro_analyzer(),
			connection->bro_analyzer()->Conn(), st);
		break;

	case PMAPPROC_SET:
		bro_event_pm_attempt_set(connection->bro_analyzer(),
			connection->bro_analyzer()->Conn(), st, call->call_val());
		break;

	case PMAPPROC_UNSET:
		bro_event_pm_attempt_unset(connection->bro_analyzer(),
			connection->bro_analyzer()->Conn(), st, call->call_val());
		break;

	case PMAPPROC_GETPORT:
		bro_event_pm_attempt_getport(connection->bro_analyzer(),
			connection->bro_analyzer()->Conn(), st, call->call_val());
		break;

	case PMAPPROC_DUMP:
		bro_event_pm_attempt_dump(connection->bro_analyzer(),
			connection->bro_analyzer()->Conn(), st);
		break;

	case PMAPPROC_CALLIT:
		bro_event_pm_attempt_callit(connection->bro_analyzer(),
			connection->bro_analyzer()->Conn(), st, call->call_val());
		break;

	default:
		return false;
	}

	return true;
	%}
