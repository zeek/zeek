// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "RE.h"

#include <stdlib.h>
#include <utility>

#include "DFA.h"
#include "CCL.h"
#include "EquivClass.h"
#include "Reporter.h"
#include "BroString.h"

CCL* curr_ccl = 0;

Specific_RE_Matcher* rem;
NFA_Machine* nfa = 0;
int case_insensitive = 0;

extern int RE_parse(void);
extern void RE_set_input(const char* str);
extern void RE_done_with_scan();

Specific_RE_Matcher::Specific_RE_Matcher(match_type arg_mt, int arg_multiline)
: equiv_class(NUM_SYM)
	{
	mt = arg_mt;
	multiline = arg_multiline;
	any_ccl = 0;
	pattern_text = 0;
	dfa = 0;
	ecs = 0;
	accepted = new AcceptingSet();
	}

Specific_RE_Matcher::~Specific_RE_Matcher()
	{
	for ( int i = 0; i < ccl_list.length(); ++i )
		delete ccl_list[i];

	Unref(dfa);
	delete [] pattern_text;
	delete accepted;
	}

CCL* Specific_RE_Matcher::AnyCCL()
	{
	if ( ! any_ccl )
		{ // Create the '.' character class.
		any_ccl = new CCL();
		if ( ! multiline )
			any_ccl->Add('\n');
		any_ccl->Negate();
		EC()->CCL_Use(any_ccl);
		}

	return any_ccl;
	}

void Specific_RE_Matcher::ConvertCCLs()
	{
	for ( int i = 0; i < ccl_list.length(); ++i )
		equiv_class.ConvertCCL(ccl_list[i]);
	}

void Specific_RE_Matcher::AddPat(const char* new_pat)
	{
	if ( mt == MATCH_EXACTLY )
		AddExactPat(new_pat);
	else
		AddAnywherePat(new_pat);
	}

void Specific_RE_Matcher::AddAnywherePat(const char* new_pat)
	{
	AddPat(new_pat, "^?(.|\\n)*(%s)", "(%s)|(^?(.|\\n)*(%s))");
	}

void Specific_RE_Matcher::AddExactPat(const char* new_pat)
	{
	AddPat(new_pat, "^?(%s)$?", "(%s)|(^?(%s)$?)");
	}

void Specific_RE_Matcher::AddPat(const char* new_pat,
				const char* orig_fmt, const char* app_fmt)
	{
	int n = strlen(new_pat);

	if ( pattern_text )
		n += strlen(pattern_text) + strlen(app_fmt);
	else
		n += strlen(orig_fmt);

	char* s = new char[n + 5 /* slop */];

	if ( pattern_text )
		sprintf(s, app_fmt, pattern_text, new_pat);
	else
		sprintf(s, orig_fmt, new_pat);

	delete [] pattern_text;
	pattern_text = s;
	}

void Specific_RE_Matcher::MakeCaseInsensitive()
	{
	const char fmt[] = "(?i:%s)";
	int n = strlen(pattern_text) + strlen(fmt);

	char* s = new char[n + 5 /* slop */];

	snprintf(s, n + 5, fmt, pattern_text);

	delete [] pattern_text;
	pattern_text = s;
	}

int Specific_RE_Matcher::Compile(int lazy)
	{
	if ( ! pattern_text )
		return 0;

	rem = this;
	RE_set_input(pattern_text);

	int parse_status = RE_parse();
	RE_done_with_scan();

	if ( parse_status )
		{
		reporter->Error("error compiling pattern /%s/", pattern_text);
		Unref(nfa);
		nfa = 0;
		return 0;
		}

	EC()->BuildECs();
	ConvertCCLs();

	dfa = new DFA_Machine(nfa, EC());

	Unref(nfa); 
	nfa = 0;

	ecs = EC()->EquivClasses();

	return 1;
	}

int Specific_RE_Matcher::CompileSet(const string_list& set, const int_list& idx)
	{
	if ( (size_t)set.length() != idx.size() )
		reporter->InternalError("compileset: lengths of sets differ");

	rem = this;

	NFA_Machine* set_nfa = 0;

	loop_over_list(set, i)
		{
		RE_set_input(set[i]);
		int parse_status = RE_parse();
		RE_done_with_scan();

		if ( parse_status )
			{
			reporter->Error("error compiling pattern /%s/", set[i]);

			if ( set_nfa && set_nfa != nfa )
				Unref(set_nfa);
			else
				Unref(nfa);

			nfa = 0;
			return 0;
			}

		nfa->FinalState()->SetAccept(idx[i]);
		set_nfa = set_nfa ? make_alternate(nfa, set_nfa) : nfa;
		}

	// Prefix the expression with a "^?".
	nfa = new NFA_Machine(new NFA_State(SYM_BOL, rem->EC()));
	nfa->MakeOptional();
	if ( set_nfa )
		nfa->AppendMachine( set_nfa );

	EC()->BuildECs();
	ConvertCCLs();

	dfa = new DFA_Machine(nfa, EC());
	ecs = EC()->EquivClasses();

	return 1;
	}

string Specific_RE_Matcher::LookupDef(const string& def)
	{
	const auto& iter = defs.find(def);
	if ( iter != defs.end() )
		return iter->second;

	return string();
	}

int Specific_RE_Matcher::MatchAll(const char* s)
	{
	return MatchAll((const u_char*)(s), strlen(s));
	}

int Specific_RE_Matcher::MatchAll(const BroString* s)
	{
	// s->Len() does not include '\0'.
	return MatchAll(s->Bytes(), s->Len());
	}

int Specific_RE_Matcher::Match(const char* s)
	{
	return Match((const u_char*)(s), strlen(s));
	}

int Specific_RE_Matcher::Match(const BroString* s)
	{
	return Match(s->Bytes(), s->Len());
	}

int Specific_RE_Matcher::LongestMatch(const char* s)
	{
	return LongestMatch((const u_char*)(s), strlen(s));
	}

int Specific_RE_Matcher::LongestMatch(const BroString* s)
	{
	return LongestMatch(s->Bytes(), s->Len());
	}

int Specific_RE_Matcher::MatchAll(const u_char* bv, int n)
	{
	if ( ! dfa )
		// An empty pattern matches "all" iff what's being
		// matched is empty.
		return n == 0;

	DFA_State* d = dfa->StartState();
	d = d->Xtion(ecs[SYM_BOL], dfa);

	while ( d )
		{
		if ( --n < 0 )
			break;

		int ec = ecs[*(bv++)];
		d = d->Xtion(ec, dfa);
		}

	if ( d )
		d = d->Xtion(ecs[SYM_EOL], dfa);

	return d && d->Accept() != 0;
	}


int Specific_RE_Matcher::Match(const u_char* bv, int n)
	{
	if ( ! dfa )
		// An empty pattern matches anything.
		return 1;

	DFA_State* d = dfa->StartState();

	d = d->Xtion(ecs[SYM_BOL], dfa);
	if ( ! d ) return 0;

	for ( int i = 0; i < n; ++i )
		{
		int ec = ecs[bv[i]];
		d = d->Xtion(ec, dfa);
		if ( ! d )
			break;

		if ( d->Accept() )
			return i + 1;
		}

	if ( d )
		{
		d = d->Xtion(ecs[SYM_EOL], dfa);
		if ( d && d->Accept() )
			return n > 0 ? n : 1;	// we can't return 0 here for match...
		}

	return 0;
	}


void Specific_RE_Matcher::Dump(FILE* f)
	{
	dfa->Dump(f);
	}

inline void RE_Match_State::AddMatches(const AcceptingSet& as,
                                       MatchPos position)
	{
	typedef std::pair<AcceptIdx, MatchPos> am_idx;

	for ( AcceptingSet::const_iterator it = as.begin(); it != as.end(); ++it )
		accepted_matches.insert(am_idx(*it, position));
	}

bool RE_Match_State::Match(const u_char* bv, int n,
				bool bol, bool eol, bool clear)
	{
	if ( current_pos == -1 )
		{
		// First call to Match().
		if ( ! dfa )
			return false;

		// Initialize state and copy the accepting states of the start
		// state into the acceptance set.
		current_state = dfa->StartState();

		const AcceptingSet* ac = current_state->Accept();

		if ( ac )
			AddMatches(*ac, 0);
		}

	else if ( clear )
		current_state = dfa->StartState();

	if ( ! current_state )
		return false;

	current_pos = 0;

	size_t old_matches = accepted_matches.size();

	int ec;
	int m = bol ? n + 1 : n;
	int e = eol ? -1 : 0;

	while ( --m >= e )
		{
		if ( m == n )
			ec = ecs[SYM_BOL];
		else if ( m == -1 )
			ec = ecs[SYM_EOL];
		else
			ec = ecs[*(bv++)];

		DFA_State* next_state = current_state->Xtion(ec,dfa);

		if ( ! next_state )
			{
			current_state = 0;
			break;
			}

		const AcceptingSet* ac = next_state->Accept();

		if ( ac )
			AddMatches(*ac, current_pos);

		++current_pos;

		current_state = next_state;
		}

	return accepted_matches.size() != old_matches;
	}

int Specific_RE_Matcher::LongestMatch(const u_char* bv, int n)
	{
	if ( ! dfa )
		// An empty pattern matches anything.
		return 0;

	// Use -1 to indicate no match.
	int last_accept = -1;
	DFA_State* d = dfa->StartState();

	d = d->Xtion(ecs[SYM_BOL], dfa);
	if ( ! d )
		return -1;

	if ( d->Accept() )
		last_accept = 0;

	for ( int i = 0; i < n; ++i )
		{
		int ec = ecs[bv[i]];
		d = d->Xtion(ec, dfa);

		if ( ! d )
			break;

		if ( d->Accept() )
			last_accept = i + 1;
		}

	if ( d )
		{
		d = d->Xtion(ecs[SYM_EOL], dfa);
		if ( d && d->Accept() )
			return n;
		}

	return last_accept;
	}

unsigned int Specific_RE_Matcher::MemoryAllocation() const
	{
	unsigned int size = 0;

	for ( int i = 0; i < ccl_list.length(); ++i )
		size += ccl_list[i]->MemoryAllocation();

	size += pad_size(sizeof(CCL*) * ccl_dict.size());
	for ( const auto& entry : ccl_dict )
		{
		size += padded_sizeof(std::string) + pad_size(sizeof(std::string::value_type) * entry.first.size());
		size += entry.second->MemoryAllocation();
		}

	for ( const auto& entry : defs )
		{
		size += padded_sizeof(std::string) + pad_size(sizeof(std::string::value_type) * entry.first.size());
		size += padded_sizeof(std::string) + pad_size(sizeof(std::string::value_type) * entry.second.size());
		}

	return size + padded_sizeof(*this)
		+ (pattern_text ? pad_size(strlen(pattern_text) + 1) : 0)
		+ ccl_list.MemoryAllocation() - padded_sizeof(ccl_list)
		+ equiv_class.Size() - padded_sizeof(EquivClass)
		+ (dfa ? dfa->MemoryAllocation() : 0) // this is ref counted; consider the bytes here?
		+ padded_sizeof(*any_ccl)
		+ padded_sizeof(*accepted) // NOLINT(bugprone-sizeof-container)
		+ accepted->size() * padded_sizeof(AcceptingSet::key_type);
	}

RE_Matcher::RE_Matcher()
	{
	re_anywhere = new Specific_RE_Matcher(MATCH_ANYWHERE);
	re_exact = new Specific_RE_Matcher(MATCH_EXACTLY);
	}

RE_Matcher::RE_Matcher(const char* pat)
	{
	re_anywhere = new Specific_RE_Matcher(MATCH_ANYWHERE);
	re_exact = new Specific_RE_Matcher(MATCH_EXACTLY);

	AddPat(pat);
	}

RE_Matcher::RE_Matcher(const char* exact_pat, const char* anywhere_pat)
	{
	re_anywhere = new Specific_RE_Matcher(MATCH_ANYWHERE);
	re_anywhere->SetPat(anywhere_pat);
	re_exact = new Specific_RE_Matcher(MATCH_EXACTLY);
	re_exact->SetPat(exact_pat);
	}

RE_Matcher::~RE_Matcher()
	{
	delete re_anywhere;
	delete re_exact;
	}

void RE_Matcher::AddPat(const char* new_pat)
	{
	re_anywhere->AddPat(new_pat);
	re_exact->AddPat(new_pat);
	}

void RE_Matcher::MakeCaseInsensitive()
	{
	re_anywhere->MakeCaseInsensitive();
	re_exact->MakeCaseInsensitive();
	}

int RE_Matcher::Compile(int lazy)
	{
	return re_anywhere->Compile(lazy) && re_exact->Compile(lazy);
	}

static RE_Matcher* matcher_merge(const RE_Matcher* re1, const RE_Matcher* re2,
				const char* merge_op)
	{
	const char* text1 = re1->PatternText();
	const char* text2 = re2->PatternText();

	int n = strlen(text1) + strlen(text2) + strlen(merge_op) + 32 /* slop */ ;

	char* merge_text = new char[n];
	snprintf(merge_text, n, "(%s)%s(%s)", text1, merge_op, text2);

	RE_Matcher* merge = new RE_Matcher(merge_text);
	delete [] merge_text;

	merge->Compile();

	return merge;
	}

RE_Matcher* RE_Matcher_conjunction(const RE_Matcher* re1, const RE_Matcher* re2)
	{
	return matcher_merge(re1, re2, "");
	}

RE_Matcher* RE_Matcher_disjunction(const RE_Matcher* re1, const RE_Matcher* re2)
	{
	return matcher_merge(re1, re2, "|");
	}
