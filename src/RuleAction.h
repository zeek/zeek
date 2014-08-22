#ifndef ruleaction_h
#define ruleaction_h

#include "BroString.h"
#include "List.h"
#include "util.h"

#include "analyzer/Tag.h"

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

class RuleActionMIME : public RuleAction {
public:
	RuleActionMIME(const char* arg_mime, int arg_strength = 0)
		{ mime = copy_string(arg_mime); strength = arg_strength; }

	virtual ~RuleActionMIME()
		{ delete [] mime; }

	virtual void DoAction(const Rule* parent, RuleEndpointState* state,
	                      const u_char* data, int len)
		{ }

	virtual void PrintDebug();

	string GetMIME() const
		{ return mime; }

	int GetStrength() const
		{ return strength; }

private:
	const char* mime;
	int strength;
};

// Base class for enable/disable actions.
class RuleActionAnalyzer : public RuleAction {
public:
	RuleActionAnalyzer(const char* analyzer);

	virtual void DoAction(const Rule* parent, RuleEndpointState* state,
			      const u_char* data, int len) = 0;

	virtual void PrintDebug();

	analyzer::Tag Analyzer() const { return analyzer; }
	analyzer::Tag ChildAnalyzer() const { return child_analyzer; }

private:
	analyzer::Tag analyzer;
	analyzer::Tag child_analyzer;
};

class RuleActionEnable : public RuleActionAnalyzer {
public:
	RuleActionEnable(const char* analyzer) : RuleActionAnalyzer(analyzer)	{}

	virtual void DoAction(const Rule* parent, RuleEndpointState* state,
				const u_char* data, int len);

	virtual void PrintDebug();
};

class RuleActionDisable : public RuleActionAnalyzer {
public:
	RuleActionDisable(const char* analyzer) : RuleActionAnalyzer(analyzer)	{}

	virtual void DoAction(const Rule* parent, RuleEndpointState* state,
				const u_char* data, int len);

	virtual void PrintDebug();
};

#endif
