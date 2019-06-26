#include "zeek-config.h"

#include "Rule.h"
#include "RuleMatcher.h"

// Start at one as we want search for this within a list,
// and List's is_member returns zero for non-membership ...
unsigned int Rule::rule_counter = 1;
unsigned int Rule::pattern_counter = 0;
rule_list Rule::rule_table;

Rule::~Rule()
	{
	delete [] id;

	loop_over_list(patterns, i)
		{
		delete [] patterns[i]->pattern;
		delete patterns[i];
		}

	loop_over_list(hdr_tests, j)
		delete hdr_tests[j];

	loop_over_list(conditions, k)
		delete conditions[k];

	loop_over_list(actions, l)
		delete actions[l];

	loop_over_list(preconds, m)
		{
		delete [] preconds[m]->id;
		delete preconds[m];
		}
	}

const char* Rule::TypeToString(Rule::PatternType type)
	{
	static const char* labels[] = {
		"File Magic", "Payload", "HTTP-REQUEST", "HTTP-REQUEST-BODY",
		"HTTP-REQUEST-HEADER", "HTTP-REPLY-BODY",
		"HTTP-REPLY-HEADER", "FTP", "Finger",
	};
	return labels[type];
	}

void Rule::PrintDebug()
	{
	fprintf(stderr, "Rule %s (%d) %s\n", id, idx, active ? "[active]" : "[disabled]");

	loop_over_list(patterns, i)
		{
		fprintf(stderr, "	%-8s |%s| (%d) \n",
			TypeToString(patterns[i]->type), patterns[i]->pattern,
			patterns[i]->id);
		}

	loop_over_list(hdr_tests, j)
		hdr_tests[j]->PrintDebug();

	loop_over_list(conditions, k)
		conditions[k]->PrintDebug();

	loop_over_list(actions, l)
		actions[l]->PrintDebug();

	fputs("\n", stderr);
	}

void Rule::AddPattern(const char* str, Rule::PatternType type,
			uint32 offset, uint32 depth)
	{
	Pattern* p = new Pattern;
	p->pattern = copy_string(str);
	p->type = type;
	p->id = ++pattern_counter;
	p->offset = offset;
	p->depth = depth;
	patterns.append(p);

	rule_table.append(this);
	}

void Rule::AddRequires(const char* id, bool opposite_direction, bool negate)
	{
	Precond* p = new Precond;
	p->id = copy_string(id);
	p->rule = 0;
	p->opposite_dir = opposite_direction;
	p->negate = negate;

	preconds.append(p);
	}

void Rule::SortHdrTests()
	{
	// FIXME: Do nothing for now - we may want to come up with
	// something clever here.
	}
