// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/RE.h"

#include "zeek/zeek-config.h"

#include <cstdlib>
#include <utility>

#include "zeek/3rdparty/doctest.h"
#include "zeek/CCL.h"
#include "zeek/DFA.h"
#include "zeek/EquivClass.h"
#include "zeek/Reporter.h"
#include "zeek/ZeekString.h"

zeek::detail::CCL* zeek::detail::curr_ccl = nullptr;
zeek::detail::Specific_RE_Matcher* zeek::detail::rem = nullptr;
zeek::detail::NFA_Machine* zeek::detail::nfa = nullptr;
bool zeek::detail::case_insensitive = false;
bool zeek::detail::re_single_line = false;

extern int RE_parse(void);
extern void RE_set_input(const char* str);
extern void RE_done_with_scan();

namespace zeek
	{
namespace detail
	{

Specific_RE_Matcher::Specific_RE_Matcher(match_type arg_mt, bool arg_multiline)
	: mt(arg_mt), multiline(arg_multiline), equiv_class(NUM_SYM)
	{
	any_ccl = nullptr;
	single_line_ccl = nullptr;
	dfa = nullptr;
	ecs = nullptr;
	accepted = new AcceptingSet();
	}

Specific_RE_Matcher::~Specific_RE_Matcher()
	{
	for ( int i = 0; i < ccl_list.length(); ++i )
		delete ccl_list[i];

	Unref(dfa);
	delete accepted;
	}

CCL* Specific_RE_Matcher::AnyCCL(bool single_line_mode)
	{
	if ( single_line_mode )
		{
		if ( ! single_line_ccl )
			{
			single_line_ccl = new CCL();
			single_line_ccl->Negate();
			EC()->CCL_Use(single_line_ccl);
			}

		return single_line_ccl;
		}

	if ( ! any_ccl )
		{
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

void Specific_RE_Matcher::AddPat(const char* new_pat, const char* orig_fmt, const char* app_fmt)
	{
	if ( ! pattern_text.empty() )
		pattern_text = util::fmt(app_fmt, pattern_text.c_str(), new_pat);
	else
		pattern_text = util::fmt(orig_fmt, new_pat);
	}

void Specific_RE_Matcher::MakeCaseInsensitive()
	{
	const char fmt[] = "(?i:%s)";
	pattern_text = util::fmt(fmt, pattern_text.c_str());
	}

void Specific_RE_Matcher::MakeSingleLine()
	{
	const char fmt[] = "(?s:%s)";
	pattern_text = util::fmt(fmt, pattern_text.c_str());
	}

bool Specific_RE_Matcher::Compile(bool lazy)
	{
	if ( pattern_text.empty() )
		return false;

	rem = this;
	RE_set_input(pattern_text.c_str());

	int parse_status = RE_parse();
	RE_done_with_scan();

	if ( parse_status )
		{
		reporter->Error("error compiling pattern /%s/", pattern_text.c_str());
		Unref(nfa);
		nfa = nullptr;
		return false;
		}

	EC()->BuildECs();
	ConvertCCLs();

	dfa = new DFA_Machine(nfa, EC());

	Unref(nfa);
	nfa = nullptr;

	ecs = EC()->EquivClasses();

	return true;
	}

bool Specific_RE_Matcher::CompileSet(const string_list& set, const int_list& idx)
	{
	if ( (size_t)set.length() != idx.size() )
		reporter->InternalError("compileset: lengths of sets differ");

	rem = this;

	NFA_Machine* set_nfa = nullptr;

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

			nfa = nullptr;
			return false;
			}

		nfa->FinalState()->SetAccept(idx[i]);
		set_nfa = set_nfa ? make_alternate(nfa, set_nfa) : nfa;
		}

	// Prefix the expression with a "^?".
	nfa = new NFA_Machine(new NFA_State(SYM_BOL, rem->EC()));
	nfa->MakeOptional();
	if ( set_nfa )
		nfa->AppendMachine(set_nfa);

	EC()->BuildECs();
	ConvertCCLs();

	dfa = new DFA_Machine(nfa, EC());
	ecs = EC()->EquivClasses();

	return true;
	}

std::string Specific_RE_Matcher::LookupDef(const std::string& def)
	{
	const auto& iter = defs.find(def);
	if ( iter != defs.end() )
		return iter->second;

	return std::string();
	}

bool Specific_RE_Matcher::MatchAll(const char* s)
	{
	return MatchAll((const u_char*)(s), strlen(s));
	}

bool Specific_RE_Matcher::MatchAll(const String* s)
	{
	// s->Len() does not include '\0'.
	return MatchAll(s->Bytes(), s->Len());
	}

int Specific_RE_Matcher::Match(const char* s)
	{
	return Match((const u_char*)(s), strlen(s));
	}

int Specific_RE_Matcher::Match(const String* s)
	{
	return Match(s->Bytes(), s->Len());
	}

int Specific_RE_Matcher::LongestMatch(const char* s)
	{
	return LongestMatch((const u_char*)(s), strlen(s));
	}

int Specific_RE_Matcher::LongestMatch(const String* s)
	{
	return LongestMatch(s->Bytes(), s->Len());
	}

bool Specific_RE_Matcher::MatchAll(const u_char* bv, int n)
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

	return d && d->Accept() != nullptr;
	}

int Specific_RE_Matcher::Match(const u_char* bv, int n)
	{
	if ( ! dfa )
		// An empty pattern matches anything.
		return 1;

	DFA_State* d = dfa->StartState();

	d = d->Xtion(ecs[SYM_BOL], dfa);
	if ( ! d )
		return 0;

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
			return n > 0 ? n : 1; // we can't return 0 here for match...
		}

	return 0;
	}

void Specific_RE_Matcher::Dump(FILE* f)
	{
	dfa->Dump(f);
	}

inline void RE_Match_State::AddMatches(const AcceptingSet& as, MatchPos position)
	{
	using am_idx = std::pair<AcceptIdx, MatchPos>;

	for ( AcceptingSet::const_iterator it = as.begin(); it != as.end(); ++it )
		accepted_matches.insert(am_idx(*it, position));
	}

bool RE_Match_State::Match(const u_char* bv, int n, bool bol, bool eol, bool clear)
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

		DFA_State* next_state = current_state->Xtion(ec, dfa);

		if ( ! next_state )
			{
			current_state = nullptr;
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

static RE_Matcher* matcher_merge(const RE_Matcher* re1, const RE_Matcher* re2, const char* merge_op)
	{
	const char* text1 = re1->PatternText();
	const char* text2 = re2->PatternText();

	size_t n = strlen(text1) + strlen(text2) + strlen(merge_op) + 32 /* slop */;

	std::string merge_text = util::fmt("(%s)%s(%s)", text1, merge_op, text2);
	RE_Matcher* merge = new RE_Matcher(merge_text.c_str());

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

	} // namespace detail

RE_Matcher::RE_Matcher()
	{
	re_anywhere = new detail::Specific_RE_Matcher(detail::MATCH_ANYWHERE);
	re_exact = new detail::Specific_RE_Matcher(detail::MATCH_EXACTLY);
	}

RE_Matcher::RE_Matcher(const char* pat) : orig_text(pat)
	{
	re_anywhere = new detail::Specific_RE_Matcher(detail::MATCH_ANYWHERE);
	re_exact = new detail::Specific_RE_Matcher(detail::MATCH_EXACTLY);

	AddPat(pat);
	}

RE_Matcher::RE_Matcher(const char* exact_pat, const char* anywhere_pat)
	{
	re_anywhere = new detail::Specific_RE_Matcher(detail::MATCH_ANYWHERE);
	re_anywhere->SetPat(anywhere_pat);
	re_exact = new detail::Specific_RE_Matcher(detail::MATCH_EXACTLY);
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

	is_case_insensitive = true;
	}

void RE_Matcher::MakeSingleLine()
	{
	re_anywhere->MakeSingleLine();
	re_exact->MakeSingleLine();

	is_single_line = true;
	}

bool RE_Matcher::Compile(bool lazy)
	{
	return re_anywhere->Compile(lazy) && re_exact->Compile(lazy);
	}

TEST_SUITE("re_matcher")
	{

	TEST_CASE("simple_pattern")
		{
		RE_Matcher match("[0-9]+");
		match.Compile();
		CHECK(strcmp(match.OrigText(), "[0-9]+") == 0);
		CHECK(strcmp(match.PatternText(), "^?([0-9]+)$?") == 0);
		CHECK(strcmp(match.AnywherePatternText(), "^?(.|\\n)*([0-9]+)") == 0);

		CHECK(match.MatchExactly("12345"));
		CHECK_FALSE(match.MatchExactly("a12345"));

		// The documentation for MatchAnywhere says that it returns the
		// "index just beyond where the first match occurs", which I would
		// think means *after* the match. This is returning the position
		// where the match starts though.
		CHECK(match.MatchAnywhere("a1234bcd") == 2);
		CHECK(match.MatchAnywhere("abcd") == 0);
		}

	TEST_CASE("case_insensitive_mode")
		{
		RE_Matcher match("[a-z]+");
		match.MakeCaseInsensitive();
		match.Compile();
		CHECK(strcmp(match.PatternText(), "(?i:^?([a-z]+)$?)") == 0);

		CHECK(match.MatchExactly("abcDEF"));
		}

	TEST_CASE("multi_pattern")
		{
		RE_Matcher match("[0-9]+");
		match.AddPat("[a-z]+");
		match.Compile();

		CHECK(strcmp(match.PatternText(), "(^?([0-9]+)$?)|(^?([a-z]+)$?)") == 0);

		CHECK(match.MatchExactly("abc"));
		CHECK(match.MatchExactly("123"));
		CHECK_FALSE(match.MatchExactly("abc123"));
		}

	TEST_CASE("modes_multi_pattern")
		{
		RE_Matcher match("[a-m]+");
		match.MakeCaseInsensitive();

		match.AddPat("[n-z]+");
		match.Compile();

		CHECK(strcmp(match.PatternText(), "((?i:^?([a-m]+)$?))|(^?([n-z]+)$?)") == 0);
		CHECK(match.MatchExactly("aBc"));
		CHECK(match.MatchExactly("nop"));
		CHECK_FALSE(match.MatchExactly("NoP"));
		}

	TEST_CASE("single_line_mode")
		{
		RE_Matcher match(".*");
		match.MakeSingleLine();
		match.Compile();

		CHECK(strcmp(match.PatternText(), "(?s:^?(.*)$?)") == 0);
		CHECK(match.MatchExactly("abc\ndef"));

		RE_Matcher match2("fOO.*bAR");
		match2.MakeSingleLine();
		match2.Compile();

		CHECK(strcmp(match2.PatternText(), "(?s:^?(fOO.*bAR)$?)") == 0);
		CHECK(match.MatchExactly("fOOab\ncdbAR"));

		RE_Matcher match3("b.r");
		match3.MakeSingleLine();
		match3.Compile();
		CHECK(match3.MatchExactly("bar"));
		CHECK(match3.MatchExactly("b\nr"));

		RE_Matcher match4("a.c");
		match4.MakeSingleLine();
		match4.AddPat("def");
		match4.Compile();
		CHECK(match4.MatchExactly("abc"));
		CHECK(match4.MatchExactly("a\nc"));
		}

	TEST_CASE("disjunction")
		{
		RE_Matcher match1("a.c");
		match1.MakeSingleLine();
		match1.Compile();
		RE_Matcher match2("def");
		match2.Compile();
		auto dj = detail::RE_Matcher_disjunction(&match1, &match2);
		CHECK(dj->MatchExactly("abc"));
		CHECK(dj->MatchExactly("a.c"));
		CHECK(dj->MatchExactly("a\nc"));
		CHECK(dj->MatchExactly("def"));
		delete dj;
		}
	}

	} // namespace zeek
