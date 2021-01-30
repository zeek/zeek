#pragma once

#include <limits.h>
#include <stdint.h>
#include <map>
#include <string>

#include "zeek/List.h"
#include "zeek/Obj.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(RuleCondition, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(RuleAction, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(RuleHdrTest, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(RuleMatcher, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Rule, zeek::detail);

namespace zeek::detail {

using rule_list = PList<Rule>;
using rule_dict = std::map<std::string, Rule*>;

class Rule {
public:
	Rule(const char* arg_id, const Location& arg_location)
		{
		id = util::copy_string(arg_id);
		idx = rule_counter++;
		location = arg_location;
		active = true;
		next = nullptr;
		}

	~Rule();

	const char* ID() const		{ return id; }
	unsigned int Index() const	{ return idx; }

	enum PatternType {
		FILE_MAGIC, PAYLOAD, HTTP_REQUEST, HTTP_REQUEST_BODY, HTTP_REQUEST_HEADER,
		HTTP_REPLY_BODY, HTTP_REPLY_HEADER, FTP, FINGER, TYPES,
	};

	bool Active()	{ return active; }
	void SetActiveStatus(bool new_status)	{ active = new_status; }
	void AddAction(RuleAction* act)		{ actions.push_back(act); }
	void AddCondition(RuleCondition* cond)	{ conditions.push_back(cond); }
	void AddHdrTest(RuleHdrTest* hdr_test)	{ hdr_tests.push_back(hdr_test);	}
	void AddPattern(const char* str, Rule::PatternType type,
			uint32_t offset = 0, uint32_t depth = INT_MAX);
	void AddRequires(const char* id, bool opposite_direction, bool negate);

	const Location& GetLocation() const	{ return location; }

	void PrintDebug();

	static const char* TypeToString(Rule::PatternType type);

private:
	friend class RuleMatcher;

	void SortHdrTests();

	using rule_action_list = PList<RuleAction>;
	using rule_condition_list = PList<RuleCondition>;
	using rule_hdr_test_list = PList<RuleHdrTest>;

	rule_hdr_test_list hdr_tests;
	rule_condition_list conditions;
	rule_action_list actions;

	// Matching of this rule can depend on the state of other rules.
	struct Precond {
		const char* id;
		Rule* rule;	// set by RuleMatcher
		bool opposite_dir;	// if true, rule must match other dir.
		bool negate;	// negate test
	};

	using precond_list = PList<Precond>;

	precond_list preconds;
	rule_list dependents;	// rules w/ us as a precondition
				// (set by RuleMatcher)

	const char* id;
	unsigned int idx;	// unique index of this rule
	bool active;	// set the active status of the rule, default true

	struct Pattern {
		char* pattern;	// the pattern itself
		PatternType type;
		int id;	// ID of pattern (for identifying it within regexps)
		uint32_t offset;
		uint32_t depth;
	};

	using pattern_list = PList<Pattern>;
	pattern_list patterns;

	Rule* next;	// Linkage within RuleHdrTest tree:
			// Ptr to next rule using the same RuleHdrTests

	Location location;

	// Rules and payloads are numbered individually.
	static unsigned int rule_counter;
	static unsigned int pattern_counter;

	// Array of rules indexed by payloadid.
	static rule_list rule_table;
	};

} // namespace zeek::detail
