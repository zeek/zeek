#ifndef rulecondition_h
#define rulecondition_h

#include "BroString.h"
#include "Func.h"
#include "List.h"
#include "util.h"

class Rule;
class RuleEndpointState;

// Base class for all rule conditions except patterns and "header".
class RuleCondition {
public:
	RuleCondition()	{ }
	virtual ~RuleCondition()	{ }

	virtual bool DoMatch(Rule* rule, RuleEndpointState* state,
				const u_char* data, int len) = 0;

	virtual void PrintDebug() = 0;
};

// Implements the "tcp-state" keyword.
class RuleConditionTCPState : public RuleCondition {
public:
	enum TCPState {
		STATE_ESTABLISHED = 1,
		STATE_ORIG = 2,
		STATE_RESP = 4,
		STATE_STATELESS = 8
	};

	explicit RuleConditionTCPState(int arg_tcpstates)
		{ tcpstates = arg_tcpstates; }

	~RuleConditionTCPState() override { }

	bool DoMatch(Rule* rule, RuleEndpointState* state,
				const u_char* data, int len) override;

	void PrintDebug() override;

private:
	int tcpstates;
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

	~RuleConditionIPOptions() override
		{ }

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
	~RuleConditionSameIP() override {}

	bool DoMatch(Rule* rule, RuleEndpointState* state,
				const u_char* data, int len) override;

	void PrintDebug() override;
};

// Implements "payload-size".
class RuleConditionPayloadSize : public RuleCondition {
public:
	enum Comp { RULE_LE, RULE_GE, RULE_LT, RULE_GT, RULE_EQ, RULE_NE };

	RuleConditionPayloadSize(uint32 arg_val, Comp arg_comp)
		{ val = arg_val; comp = arg_comp; }

	~RuleConditionPayloadSize() override {}

	bool DoMatch(Rule* rule, RuleEndpointState* state,
				const u_char* data, int len) override;

	void PrintDebug() override;

private:
	uint32 val;
	Comp comp;
};

// Implements "eval" which evaluates the given Bro identifier.
class RuleConditionEval : public RuleCondition {
public:
	explicit RuleConditionEval(const char* func);
	~RuleConditionEval() override {}

	bool DoMatch(Rule* rule, RuleEndpointState* state,
				const u_char* data, int len) override;

	void PrintDebug() override;
private:
	ID* id;
};



#endif
