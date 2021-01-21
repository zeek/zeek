#pragma once

#include <stdint.h> // for u_char
#include <sys/types.h> // for u_char

#include "zeek/util.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(RuleEndpointState, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Rule, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(ID, zeek::detail);

namespace zeek::detail {

// Base class for all rule conditions except patterns and "header".
class RuleCondition {
public:
	RuleCondition()	{ }
	virtual ~RuleCondition()	{ }

	virtual bool DoMatch(Rule* rule, RuleEndpointState* state,
				const u_char* data, int len) = 0;

	virtual void PrintDebug() = 0;
};

enum RuleStateKind {
	RULE_STATE_ESTABLISHED = 1,
	RULE_STATE_ORIG = 2,
	RULE_STATE_RESP = 4,
	RULE_STATE_STATELESS = 8
};

// Implements the "tcp-state" keyword.
class RuleConditionTCPState : public RuleCondition {
public:
	explicit RuleConditionTCPState(int arg_tcpstates)
		{ tcpstates = arg_tcpstates; }

	bool DoMatch(Rule* rule, RuleEndpointState* state,
				const u_char* data, int len) override;

	void PrintDebug() override;

private:
	int tcpstates;
};

// Implements the "udp-state" keyword.
class RuleConditionUDPState : public RuleCondition {
public:
	explicit RuleConditionUDPState(int arg_states)
		{ states = arg_states; }

	bool DoMatch(Rule* rule, RuleEndpointState* state, const u_char* data,
	             int len) override;

	void PrintDebug() override;

private:
	int states;
};

// Implements "ip-options".
class RuleConditionIPOptions : public RuleCondition {
public:
	enum Options {
		OPT_LSRR = 1,
		OPT_LSRRE = 2,
		OPT_RR = 4,
		OPT_SSRR = 8,
	};

	explicit RuleConditionIPOptions(int arg_options)	{ options = arg_options; }

	bool DoMatch(Rule* rule, RuleEndpointState* state,
				const u_char* data, int len) override;

	void PrintDebug() override;

private:
	int options;
};

// Implements "same-ip".
class RuleConditionSameIP : public RuleCondition {
public:
	RuleConditionSameIP()	{ }

	bool DoMatch(Rule* rule, RuleEndpointState* state,
				const u_char* data, int len) override;

	void PrintDebug() override;
};

// Implements "payload-size".
class RuleConditionPayloadSize : public RuleCondition {
public:
	enum Comp { RULE_LE, RULE_GE, RULE_LT, RULE_GT, RULE_EQ, RULE_NE };

	RuleConditionPayloadSize(uint32_t arg_val, Comp arg_comp)
		{ val = arg_val; comp = arg_comp; }

	bool DoMatch(Rule* rule, RuleEndpointState* state,
				const u_char* data, int len) override;

	void PrintDebug() override;

private:
	uint32_t val;
	Comp comp;
};

// Implements "eval" which evaluates the given Bro identifier.
class RuleConditionEval : public RuleCondition {
public:
	explicit RuleConditionEval(const char* func);

	bool DoMatch(Rule* rule, RuleEndpointState* state,
				const u_char* data, int len) override;

	void PrintDebug() override;
private:
	ID* id;
};

} // namespace zeek::detail
