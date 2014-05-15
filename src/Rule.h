#ifndef rule_h
#define rule_h

#include <limits.h>

#include "Obj.h"
#include "List.h"
#include "Dict.h"
#include "util.h"

class RuleCondition;
class RuleAction;
class RuleHdrTest;

class Rule;

declare(PList, Rule);
typedef PList(Rule) rule_list;

declare(PDict, Rule);
typedef PDict(Rule) rule_dict;

class Rule {
public:
	Rule(const char* arg_id, const Location& arg_location)
		{
		id = copy_string(arg_id);
		idx = rule_counter++;
		location = arg_location;
		active = true;
		next = 0;
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
	void AddAction(RuleAction* act)		{ actions.append(act); }
	void AddCondition(RuleCondition* cond)	{ conditions.append(cond); }
	void AddHdrTest(RuleHdrTest* hdr_test)	{ hdr_tests.append(hdr_test);	}
	void AddPattern(const char* str, Rule::PatternType type,
			uint32 offset = 0, uint32 depth = INT_MAX);
	void AddRequires(const char* id, bool opposite_direction, bool negate);

	const Location& GetLocation() const	{ return location; }

	void PrintDebug();

	static const char* TypeToString(Rule::PatternType type);

private:
	friend class RuleMatcher;

	void SortHdrTests();

	declare(PList, RuleAction);
	typedef PList(RuleAction) rule_action_list;

	declare(PList, RuleCondition);
	typedef PList(RuleCondition) rule_condition_list;

	declare(PList, RuleHdrTest);
	typedef PList(RuleHdrTest) rule_hdr_test_list;

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

	declare(PList, Precond);
	typedef PList(Precond) precond_list;

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
		uint32 offset;
		uint32 depth;
	};

	declare(PList, Pattern);
	typedef PList(Pattern) pattern_list;
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

#endif
