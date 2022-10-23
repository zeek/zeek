#include "zeek/RuleCondition.h"

#include "zeek/zeek-config.h"

#include "zeek/Func.h"
#include "zeek/ID.h"
#include "zeek/Reporter.h"
#include "zeek/RuleMatcher.h"
#include "zeek/Scope.h"
#include "zeek/Val.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

static inline bool is_established(const zeek::analyzer::tcp::TCP_Endpoint* e)
	{
	// We more or less follow Snort here: an established session
	// is one for which the initial handshake has succeeded (but we
	// add partial connections).  The connection tear-down is part
	// of the connection.
	return e->state != zeek::analyzer::tcp::TCP_ENDPOINT_INACTIVE &&
	       e->state != zeek::analyzer::tcp::TCP_ENDPOINT_SYN_SENT &&
	       e->state != zeek::analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT;
	}

namespace zeek::detail
	{

bool RuleConditionTCPState::DoMatch(Rule* rule, RuleEndpointState* state, const u_char* data,
                                    int len)
	{
	auto* adapter = state->GetAnalyzer()->Conn()->GetSessionAdapter();

	if ( ! adapter || ! adapter->IsAnalyzer("TCP") )
		return false;

	auto* ta = static_cast<packet_analysis::TCP::TCPSessionAdapter*>(adapter);

	if ( tcpstates & RULE_STATE_STATELESS )
		return true;

	if ( (tcpstates & RULE_STATE_ORIG) && ! state->IsOrig() )
		return false;

	if ( (tcpstates & RULE_STATE_RESP) && state->IsOrig() )
		return false;

	if ( (tcpstates & RULE_STATE_ESTABLISHED) &&
	     ! (is_established(ta->Orig()) && is_established(ta->Resp())) )
		return false;

	return true;
	}

void RuleConditionTCPState::PrintDebug()
	{
	fprintf(stderr, "	RuleConditionTCPState: 0x%x\n", tcpstates);
	}

bool RuleConditionUDPState::DoMatch(Rule* rule, RuleEndpointState* state, const u_char* data,
                                    int len)
	{
	auto* adapter = state->GetAnalyzer()->Conn()->GetSessionAdapter();

	if ( ! adapter || ! adapter->IsAnalyzer("UDP") )
		return false;

	if ( states & RULE_STATE_STATELESS )
		return true;

	if ( (states & RULE_STATE_ORIG) && ! state->IsOrig() )
		return false;

	if ( (states & RULE_STATE_RESP) && state->IsOrig() )
		return false;

	return true;
	}

void RuleConditionUDPState::PrintDebug()
	{
	fprintf(stderr, "	RuleConditionUDPState: 0x%x\n", states);
	}

void RuleConditionIPOptions::PrintDebug()
	{
	fprintf(stderr, "	RuleConditionIPOptions: 0x%x\n", options);
	}

bool RuleConditionIPOptions::DoMatch(Rule* rule, RuleEndpointState* state, const u_char* data,
                                     int len)
	{
	// FIXME: Not implemented yet
	return false;
	}

void RuleConditionSameIP::PrintDebug()
	{
	fprintf(stderr, "	RuleConditionSameIP\n");
	}

bool RuleConditionSameIP::DoMatch(Rule* rule, RuleEndpointState* state, const u_char* data, int len)
	{
	return state->GetAnalyzer()->Conn()->OrigAddr() == state->GetAnalyzer()->Conn()->RespAddr();
	}

void RuleConditionPayloadSize::PrintDebug()
	{
	fprintf(stderr, "	RuleConditionPayloadSize %d\n", val);
	}

bool RuleConditionPayloadSize::DoMatch(Rule* rule, RuleEndpointState* state, const u_char* data,
                                       int len)
	{
#ifdef MATCHER_PRINT_DEBUG
	fprintf(stderr, "%.06f PayloadSize check: val = %d, payload_size = %d\n", network_time, val,
	        state->PayloadSize());
#endif

	if ( state->PayloadSize() < 0 )
		// The size has not been set yet, i.e. we're matching
		// on the pure rules now.
		return false;

	if ( state->PayloadSize() == 0 )
		// We are interested in the first non-empty chunk.
		return false;

	uint32_t payload_size = uint32_t(state->PayloadSize());

	switch ( comp )
		{
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
			reporter->InternalError("unknown comparison type");
		}

	// Should not be reached
	return false;
	}

RuleConditionEval::RuleConditionEval(const char* func)
	{
	id = global_scope()->Find(func).get();
	if ( ! id )
		{
		rules_error("unknown identifier", func);
		return;
		}

	if ( id->GetType()->Tag() == TYPE_FUNC )
		{
		// Validate argument quantity and type.
		FuncType* f = id->GetType()->AsFuncType();

		if ( f->Yield()->Tag() != TYPE_BOOL )
			rules_error("eval function type must yield a 'bool'", func);

		static auto signature_state = id::find_type<RecordType>("signature_state");
		TypeList tl;
		tl.Append(signature_state);
		tl.Append(base_type(TYPE_STRING));

		if ( ! f->CheckArgs(tl.GetTypes()) )
			rules_error("eval function parameters must be a 'signature_state' "
			            "and a 'string' type",
			            func);

		std::vector<AttrPtr> attrv{make_intrusive<Attr>(ATTR_IS_USED, nullptr)};
		id->AddAttrs(
			make_intrusive<Attributes>(std::move(attrv), id->GetType(), false, id->IsGlobal()));
		}
	}

bool RuleConditionEval::DoMatch(Rule* rule, RuleEndpointState* state, const u_char* data, int len)
	{
	if ( ! id->HasVal() )
		{
		reporter->Error("undefined value");
		return false;
		}

	if ( id->GetType()->Tag() != TYPE_FUNC )
		return id->GetVal()->AsBool();

	// Call function with a signature_state value as argument.
	Args args;
	args.reserve(2);
	args.emplace_back(AdoptRef{}, rule_matcher->BuildRuleStateValue(rule, state));

	if ( data )
		args.emplace_back(make_intrusive<StringVal>(len, (const char*)data));
	else
		args.emplace_back(val_mgr->EmptyString());

	bool result = false;

	try
		{
		auto val = id->GetVal()->AsFunc()->Invoke(&args);
		result = val && val->AsBool();
		}

	catch ( InterpreterException& e )
		{
		}

	return result;
	}

void RuleConditionEval::PrintDebug()
	{
	fprintf(stderr, "	RuleConditionEval: %s\n", id->Name());
	}

	} // namespace zeek::detail
