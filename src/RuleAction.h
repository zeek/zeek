#ifndef ruleaction_h
#define ruleaction_h

#include "AnalyzerTags.h"
#include "BroString.h"
#include "List.h"
#include "util.h"

class Rule;
class RuleEndpointState;

// Base class of all rule actions.
class RuleAction {
public:
	RuleAction()	{ }
	virtual ~RuleAction()	{ }

	virtual void DoAction(const Rule* parent, RuleEndpointState* state,
				const u_char* data, int len) = 0;
	virtual void PrintDebug() = 0;
};

// Implements the "event" keyword.
class RuleActionEvent : public RuleAction {
public:
	RuleActionEvent(const char* arg_msg)	{ msg = copy_string(arg_msg); }
	virtual ~RuleActionEvent()	{ delete [] msg; }

	virtual void DoAction(const Rule* parent, RuleEndpointState* state,
				const u_char* data, int len);

	virtual void PrintDebug();

private:
	const char* msg;
};

// Base class for DPM enable/disable actions.
class RuleActionDPM : public RuleAction {
public:
	RuleActionDPM(const char* analyzer);

	virtual void DoAction(const Rule* parent, RuleEndpointState* state,
			      const u_char* data, int len) = 0;

	virtual void PrintDebug();

	AnalyzerTag::Tag Analyzer() const { return analyzer; }
	AnalyzerTag::Tag ChildAnalyzer() const { return child_analyzer; }

private:
	// FIXME: This is in fact an AnalyzerID but we can't include "Analyzer.h"
	// at this point due to circular dependenides. Fix that!
	AnalyzerTag::Tag analyzer;
	AnalyzerTag::Tag child_analyzer;
};

class RuleActionEnable : public RuleActionDPM {
public:
	RuleActionEnable(const char* analyzer) : RuleActionDPM(analyzer)	{}

	virtual void DoAction(const Rule* parent, RuleEndpointState* state,
				const u_char* data, int len);

	virtual void PrintDebug();
};

class RuleActionDisable : public RuleActionDPM {
public:
	RuleActionDisable(const char* analyzer) : RuleActionDPM(analyzer)	{}

	virtual void DoAction(const Rule* parent, RuleEndpointState* state,
				const u_char* data, int len);

	virtual void PrintDebug();
};

#endif
