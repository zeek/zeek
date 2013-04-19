#include "config.h"

#include "RuleCondition.h"
#include "analyzer/protocol/tcp/TCP.h"
#include "Scope.h"

static inline bool is_established(const analyzer::tcp::TCP_Endpoint* e)
	{
	// We more or less follow Snort here: an established session
	// is one for which the initial handshake has succeded (but we
	// add partial connections).  The connection tear-down is part
	// of the connection.
	return e->state != analyzer::tcp::TCP_ENDPOINT_INACTIVE &&
	       e->state != analyzer::tcp::TCP_ENDPOINT_SYN_SENT &&
	       e->state != analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT;
	}

bool RuleConditionTCPState::DoMatch(Rule* rule, RuleEndpointState* state,
					const u_char* data, int len)
	{
	analyzer::Analyzer* root = state->GetAnalyzer()->Conn()->GetRootAnalyzer();

	if ( ! root || ! root->IsAnalyzer("TCP") )
		return false;

	analyzer::tcp::TCP_Analyzer* ta = static_cast<analyzer::tcp::TCP_Analyzer*>(root);

	if ( tcpstates & STATE_STATELESS )
		return true;

	if ( (tcpstates & STATE_ORIG) && ! state->IsOrig() )
		return false;

	if ( (tcpstates & STATE_RESP) && state->IsOrig() )
		return false;

	if ( (tcpstates & STATE_ESTABLISHED ) &&
		! (is_established(ta->Orig()) &&
		   is_established(ta->Resp())))
		return false;

	return true;
	}

void RuleConditionTCPState::PrintDebug()
	{
	fprintf(stderr, "	RuleConditionTCPState: 0x%x\n", tcpstates);
	}

void RuleConditionIPOptions::PrintDebug()
	{
	fprintf(stderr, "	RuleConditionIPOptions: 0x%x\n", options);
	}

bool RuleConditionIPOptions::DoMatch(Rule* rule, RuleEndpointState* state,
					const u_char* data, int len)
	{
	// FIXME: Not implemented yet
	return false;
	}

void RuleConditionSameIP::PrintDebug()
	{
	fprintf(stderr, "	RuleConditionSameIP\n");
	}

bool RuleConditionSameIP::DoMatch(Rule* rule, RuleEndpointState* state,
					const u_char* data, int len)
	{
	return state->GetAnalyzer()->Conn()->OrigAddr() ==
		state->GetAnalyzer()->Conn()->RespAddr();
	}

void RuleConditionPayloadSize::PrintDebug()
	{
	fprintf(stderr, "	RuleConditionPayloadSize %d\n", val);
	}

bool RuleConditionPayloadSize::DoMatch(Rule* rule, RuleEndpointState* state,
					const u_char* data, int len)
	{
#ifdef MATCHER_PRINT_DEBUG
	fprintf(stderr, "%.06f PayloadSize check: val = %d, payload_size = %d\n",
		network_time, val, state->PayloadSize());
#endif

	if ( state->PayloadSize() < 0 )
		// The size has not been set yet, i.e. we're matching
		// on the pure rules now.
		return false;

	uint32 payload_size = uint32(state->PayloadSize());

	switch ( comp ) {
	case RULE_EQ:
		return payload_size == val;

	case RULE_NE:
		return payload_size != val;

	case RULE_LT:
		return payload_size < val;

	case RULE_GT:
		return payload_size > val;

	case RULE_LE:
		return payload_size <= val;

	case RULE_GE:
		return payload_size >= val;

	default:
		reporter->InternalError("unknown comparision type");
	}

	// Should not be reached
	return false;
	}

RuleConditionEval::RuleConditionEval(const char* func)
	{
	id = global_scope()->Lookup(func);
	if ( ! id )
		{
		rules_error("unknown identifier", func);
		return;
		}

	if ( id->Type()->Tag() == TYPE_FUNC )
		{
		// Validate argument quantity and type.
		FuncType* f = id->Type()->AsFuncType();

		if ( f->YieldType()->Tag() != TYPE_BOOL )
			rules_error("eval function type must yield a 'bool'", func);

		TypeList tl;
		tl.Append(internal_type("signature_state")->Ref());
		tl.Append(base_type(TYPE_STRING));

		if ( ! f->CheckArgs(tl.Types()) )
			rules_error("eval function parameters must be a 'signature_state' "
			            "and a 'string' type", func);
		}
	}

bool RuleConditionEval::DoMatch(Rule* rule, RuleEndpointState* state,
					const u_char* data, int len)
	{
	if ( ! id->HasVal() )
		{
		reporter->Error("undefined value");
		return false;
		}

	if ( id->Type()->Tag() != TYPE_FUNC )
		return id->ID_Val()->AsBool();

	// Call function with a signature_state value as argument.
	val_list args;
	args.append(rule_matcher->BuildRuleStateValue(rule, state));

	if ( data )
		args.append(new StringVal(len, (const char*) data));
	else
		args.append(new StringVal(""));

	bool result = 0;

	try
		{
		Val* val = id->ID_Val()->AsFunc()->Call(&args);
		result = val->AsBool();
		Unref(val);
		}

	catch ( InterpreterException& e )
		{
		result = false;
		}

	return result;
	}

void RuleConditionEval::PrintDebug()
	{
	fprintf(stderr, "	RuleConditionEval: %s\n", id->Name());
	}

