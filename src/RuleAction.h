#pragma once

#include "analyzer/Tag.h"

#include <string>

#include <sys/types.h> // for u_char

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
	explicit RuleActionEvent(const char* arg_msg);
	~RuleActionEvent() override { delete [] msg; }

	void DoAction(const Rule* parent, RuleEndpointState* state,
				const u_char* data, int len) override;

	void PrintDebug() override;

private:
	const char* msg;
};

class RuleActionMIME : public RuleAction {
public:
	explicit RuleActionMIME(const char* arg_mime, int arg_strength = 0);

	~RuleActionMIME() override
		{ delete [] mime; }

	void DoAction(const Rule* parent, RuleEndpointState* state,
	                      const u_char* data, int len) override
		{ }

	void PrintDebug() override;

	std::string GetMIME() const
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
	explicit RuleActionAnalyzer(const char* analyzer);

	void DoAction(const Rule* parent, RuleEndpointState* state,
			      const u_char* data, int len) override = 0;

	void PrintDebug() override;

	zeek::analyzer::Tag Analyzer() const { return analyzer; }
	zeek::analyzer::Tag ChildAnalyzer() const { return child_analyzer; }

private:
	zeek::analyzer::Tag analyzer;
	zeek::analyzer::Tag child_analyzer;
};

class RuleActionEnable : public RuleActionAnalyzer {
public:
	explicit RuleActionEnable(const char* analyzer) : RuleActionAnalyzer(analyzer)	{}

	void DoAction(const Rule* parent, RuleEndpointState* state,
				const u_char* data, int len) override;

	void PrintDebug() override;
};

class RuleActionDisable : public RuleActionAnalyzer {
public:
	explicit RuleActionDisable(const char* analyzer) : RuleActionAnalyzer(analyzer)	{}

	void DoAction(const Rule* parent, RuleEndpointState* state,
				const u_char* data, int len) override;

	void PrintDebug() override;
};
