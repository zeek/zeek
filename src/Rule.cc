#include "zeek/Rule.h"

#include "zeek/zeek-config.h"

#include "zeek/RuleAction.h"
#include "zeek/RuleCondition.h"
#include "zeek/RuleMatcher.h"

namespace zeek::detail
	{

// Start at one as we want search for this within a list,
// and List's is_member returns zero for non-membership ...
unsigned int Rule::rule_counter = 1;
unsigned int Rule::pattern_counter = 0;
rule_list Rule::rule_table;

Rule::~Rule()
	{
	delete[] id;

	for ( const auto& p : patterns )
		{
		delete[] p->pattern;
		delete p;
		}

	for ( const auto& test : hdr_tests )
		delete test;

	for ( const auto& cond : conditions )
		delete cond;

	for ( const auto& action : actions )
		delete action;

	for ( const auto& prec : preconds )
		{
		delete[] prec->id;
		delete prec;
		}
	}

const char* Rule::TypeToString(Rule::PatternType type)
	{
	static const char* labels[] = {
		"File Magic",
		"Payload",
		"HTTP-REQUEST",
		"HTTP-REQUEST-BODY",
		"HTTP-REQUEST-HEADER",
		"HTTP-REPLY-BODY",
		"HTTP-REPLY-HEADER",
		"FTP",
		"Finger",
	};
	return labels[type];
	}

void Rule::PrintDebug()
	{
	fprintf(stderr, "Rule %s (%d) %s\n", id, idx, active ? "[active]" : "[disabled]");

	for ( const auto& p : patterns )
		{
		fprintf(stderr, "	%-8s |%s| (%d) \n", TypeToString(p->type), p->pattern, p->id);
		}

	for ( const auto& h : hdr_tests )
		h->PrintDebug();

	for ( const auto& c : conditions )
		c->PrintDebug();

	for ( const auto& a : actions )
		a->PrintDebug();

	fputs("\n", stderr);
	}

void Rule::AddPattern(const char* str, Rule::PatternType type, uint32_t offset, uint32_t depth)
	{
	Pattern* p = new Pattern;
	p->pattern = util::copy_string(str);
	p->type = type;
	p->id = ++pattern_counter;
	p->offset = offset;
	p->depth = depth;
	patterns.push_back(p);

	rule_table.push_back(this);
	}

void Rule::AddRequires(const char* id, bool opposite_direction, bool negate)
	{
	Precond* p = new Precond;
	p->id = util::copy_string(id);
	p->rule = nullptr;
	p->opposite_dir = opposite_direction;
	p->negate = negate;

	preconds.push_back(p);
	}

void Rule::SortHdrTests()
	{
	// FIXME: Do nothing for now - we may want to come up with
	// something clever here.
	}

	} // namespace zeek::detail
