// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/RE.h"

#include <cstdlib>
#include <memory>
#include <utility>

#include "zeek/CCL.h"
#include "zeek/DFA.h"
#include "zeek/EquivClass.h"
#include "zeek/Reporter.h"
#include "zeek/ZeekString.h"

#include "zeek/3rdparty/doctest.h"

zeek::detail::CCL* zeek::detail::curr_ccl = nullptr;
zeek::detail::Specific_RE_Matcher* zeek::detail::rem = nullptr;
zeek::detail::NFA_Machine* zeek::detail::nfa = nullptr;
bool zeek::detail::case_insensitive = false;
bool zeek::detail::re_single_line = false;

extern int RE_parse();
extern void RE_set_input(const char* str);
extern void RE_done_with_scan();

namespace zeek {
namespace detail {

extern bool re_syntax_error;

Specific_RE_Matcher::Specific_RE_Matcher(match_type arg_mt, bool arg_multiline)
    : mt(arg_mt), multiline(arg_multiline), equiv_class(NUM_SYM) {
    any_ccl = nullptr;
    single_line_ccl = nullptr;
    dfa = nullptr;
    ecs = nullptr;
    accepted = new AcceptingSet();
    NFA_State::StartNewNFA();
}

Specific_RE_Matcher::~Specific_RE_Matcher() {
    for ( int i = 0; i < ccl_list.length(); ++i )
        delete ccl_list[i];

    Unref(dfa);
    delete accepted;
}

CCL* Specific_RE_Matcher::AnyCCL(bool single_line_mode) {
    if ( single_line_mode ) {
        if ( ! single_line_ccl ) {
            single_line_ccl = new CCL();
            single_line_ccl->Negate();
            EC()->CCL_Use(single_line_ccl);
        }

        return single_line_ccl;
    }

    if ( ! any_ccl ) {
        any_ccl = new CCL();
        if ( ! multiline )
            any_ccl->Add('\n');
        any_ccl->Negate();
        EC()->CCL_Use(any_ccl);
    }

    return any_ccl;
}

void Specific_RE_Matcher::ConvertCCLs() {
    for ( int i = 0; i < ccl_list.length(); ++i )
        equiv_class.ConvertCCL(ccl_list[i]);
}

void Specific_RE_Matcher::AddPat(const char* new_pat) {
    if ( mt == MATCH_EXACTLY )
        AddExactPat(new_pat);
    else
        AddAnywherePat(new_pat);
}

void Specific_RE_Matcher::AddAnywherePat(const char* new_pat) {
    AddPat(new_pat, "^?(.|\\n)*(%s)", "(%s)|(^?(.|\\n)*(%s))");
}

void Specific_RE_Matcher::AddExactPat(const char* new_pat) { AddPat(new_pat, "^?(%s)$?", "(%s)|(^?(%s)$?)"); }

void Specific_RE_Matcher::AddPat(const char* new_pat, const char* orig_fmt, const char* app_fmt) {
    if ( ! pattern_text.empty() )
        pattern_text = util::fmt(app_fmt, pattern_text.c_str(), new_pat);
    else
        pattern_text = util::fmt(orig_fmt, new_pat);
}

void Specific_RE_Matcher::MakeCaseInsensitive() {
    const char fmt[] = "(?i:%s)";
    pattern_text = util::fmt(fmt, pattern_text.c_str());
}

void Specific_RE_Matcher::MakeSingleLine() {
    const char fmt[] = "(?s:%s)";
    pattern_text = util::fmt(fmt, pattern_text.c_str());
}

bool Specific_RE_Matcher::Compile(bool lazy) {
    if ( pattern_text.empty() )
        return false;

    rem = this;
    zeek::detail::re_syntax_error = false;
    RE_set_input(pattern_text.c_str());

    int parse_status = RE_parse();
    RE_done_with_scan();

    if ( parse_status || zeek::detail::re_syntax_error ) {
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

bool Specific_RE_Matcher::CompileSet(const string_list& set, const int_list& idx) {
    if ( set.length() != static_cast<int>(idx.size()) )
        reporter->InternalError("compileset: lengths of sets differ");

    rem = this;

    NFA_Machine* set_nfa = nullptr;

    loop_over_list(set, i) {
        RE_set_input(set[i]);
        int parse_status = RE_parse();
        RE_done_with_scan();

        if ( parse_status ) {
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

    // dfa took ownership
    Unref(nfa);
    nfa = nullptr;

    return true;
}

std::string Specific_RE_Matcher::LookupDef(const std::string& def) {
    const auto& iter = defs.find(def);
    if ( iter != defs.end() )
        return iter->second;

    return {};
}

bool Specific_RE_Matcher::MatchAll(const char* s) { return MatchAll(std::string_view{s}); }

bool Specific_RE_Matcher::MatchAll(const String* s) { return MatchAll(s->ToStdStringView()); }

bool Specific_RE_Matcher::MatchAll(std::string_view sv) {
    return MatchAll(reinterpret_cast<const u_char*>(sv.data()), sv.size());
}

bool Specific_RE_Matcher::MatchSet(const String* s, std::vector<AcceptIdx>& matches) {
    return MatchAll(s->Bytes(), s->Len(), &matches);
}

bool Specific_RE_Matcher::MatchSet(std::string_view sv, std::vector<AcceptIdx>& matches) {
    return MatchAll(reinterpret_cast<const u_char*>(sv.data()), sv.size(), &matches);
}

int Specific_RE_Matcher::Match(const char* s) { return Match(std::string_view{s}); }

int Specific_RE_Matcher::Match(const String* s) { return Match(s->ToStdStringView()); }

int Specific_RE_Matcher::Match(std::string_view sv) {
    return Match(reinterpret_cast<const u_char*>(sv.data()), sv.size());
}

int Specific_RE_Matcher::LongestMatch(const char* s) { return LongestMatch(std::string_view{s}); }

int Specific_RE_Matcher::LongestMatch(const String* s) { return LongestMatch(s->ToStdStringView()); }

int Specific_RE_Matcher::LongestMatch(std::string_view sv) {
    return LongestMatch(reinterpret_cast<const u_char*>(sv.data()), sv.size());
}

bool Specific_RE_Matcher::MatchAll(const u_char* bv, int n, std::vector<AcceptIdx>* matches) {
    if ( ! dfa )
        // An empty pattern matches "all" iff what's being
        // matched is empty.
        return n == 0;

    DFA_State* d = dfa->StartState();
    d = d->Xtion(ecs[SYM_BOL], dfa);

    while ( d ) {
        if ( --n < 0 )
            break;

        int ec = ecs[*(bv++)];
        d = d->Xtion(ec, dfa);
    }

    if ( d )
        d = d->Xtion(ecs[SYM_EOL], dfa);

    if ( d && matches )
        if ( const auto* a_set = d->Accept() )
            for ( auto a : *a_set )
                matches->push_back(a);

    return d && d->Accept() != nullptr;
}

int Specific_RE_Matcher::Match(const u_char* bv, int n) {
    if ( ! dfa )
        // An empty pattern matches anything.
        return 1;

    DFA_State* d = dfa->StartState();

    d = d->Xtion(ecs[SYM_BOL], dfa);
    if ( ! d )
        return 0;

    for ( int i = 0; i < n; ++i ) {
        int ec = ecs[bv[i]];
        d = d->Xtion(ec, dfa);
        if ( ! d )
            break;

        if ( d->Accept() )
            return i + 1;
    }

    if ( d ) {
        d = d->Xtion(ecs[SYM_EOL], dfa);
        if ( d && d->Accept() )
            return n > 0 ? n : 1; // we can't return 0 here for match...
    }

    return 0;
}

void Specific_RE_Matcher::Dump(FILE* f) { dfa->Dump(f); }

inline void RE_Match_State::AddMatches(const AcceptingSet& as, MatchPos position) {
    using am_idx = std::pair<AcceptIdx, MatchPos>;

    for ( const auto& entry : as )
        accepted_matches.insert(am_idx(entry, position));
}

bool RE_Match_State::Match(const u_char* bv, int n, bool bol, bool eol, bool clear) {
    if ( current_pos == -1 ) {
        // First call to Match().
        if ( ! dfa )
            return false;

        // Initialize state and copy the accepting states of the start
        // state into the acceptance set.
        current_pos = 0;
        current_state = dfa->StartState();

        const AcceptingSet* ac = current_state->Accept();

        if ( ac )
            AddMatches(*ac, 0);
    }

    else if ( clear ) {
        current_pos = 0;
        current_state = dfa->StartState();
    }

    if ( ! current_state )
        return false;


    size_t old_matches = accepted_matches.size();

    int ec;
    int m = bol ? n + 1 : n;
    int e = eol ? -1 : 0;

    while ( --m >= e ) {
        if ( m == n )
            ec = ecs[SYM_BOL];
        else if ( m == -1 )
            ec = ecs[SYM_EOL];
        else
            ec = ecs[*(bv++)];

        DFA_State* next_state = current_state->Xtion(ec, dfa);

        if ( ! next_state ) {
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

Streaming_RE_Matcher::Streaming_RE_Matcher(Specific_RE_Matcher* matcher) {
    dfa = matcher->DFA();
    ecs = matcher->EC()->EquivClasses();
    current_state = nullptr;
    current_pos = -1;
    last_accept_pos = -1;
}

Streaming_RE_Matcher::Status Streaming_RE_Matcher::FeedForFirstMatch(const u_char* bv, int n, bool bol, bool eol) {
    if ( ! dfa ) {
        if ( current_pos == -1 ) {
            current_pos = 0;
            last_accept_pos = 0;
        }
        return JAMMED;
    }

    if ( current_pos == -1 ) {
        current_pos = 0;
        current_state = dfa->StartState();

        if ( bol ) {
            current_state = current_state->Xtion(ecs[SYM_BOL], dfa);
            if ( ! current_state )
                return JAMMED;
        }

        if ( current_state->Accept() ) {
            last_accept_pos = 0;
            current_state = nullptr;
            return JAMMED;
        }
    }

    if ( ! current_state )
        return JAMMED;

    for ( int i = 0; i < n; ++i ) {
        int ec = ecs[bv[i]];
        DFA_State* next_state = current_state->Xtion(ec, dfa);

        if ( ! next_state ) {
            current_state = nullptr;
            return JAMMED;
        }

        current_state = next_state;
        ++current_pos;

        if ( current_state->Accept() ) {
            last_accept_pos = current_pos;
            current_state = nullptr;
            return JAMMED;
        }
    }

    if ( eol ) {
        DFA_State* eol_state = current_state->Xtion(ecs[SYM_EOL], dfa);
        if ( eol_state && eol_state->Accept() )
            last_accept_pos = current_pos;
        current_state = nullptr;
        return JAMMED;
    }

    return ALIVE;
}

Streaming_RE_Matcher::Status Streaming_RE_Matcher::Feed(const u_char* bv, int n, bool bol, bool eol) {
    if ( ! dfa ) {
        if ( current_pos == -1 ) {
            current_pos = 0;
            last_accept_pos = 0;
        }
        return JAMMED;
    }

    if ( current_pos == -1 ) {
        current_pos = 0;
        current_state = dfa->StartState();

        if ( bol ) {
            current_state = current_state->Xtion(ecs[SYM_BOL], dfa);
            if ( ! current_state )
                return JAMMED;
        }

        if ( current_state->Accept() ) {
            last_accept_pos = 0;
            if ( current_state->IsTerminal() ) {
                current_state = nullptr;
                return JAMMED;
            }
        }
    }

    if ( ! current_state )
        return JAMMED;

    for ( int i = 0; i < n; ++i ) {
        int ec = ecs[bv[i]];
        DFA_State* next_state = current_state->Xtion(ec, dfa);

        if ( ! next_state ) {
            current_state = nullptr;
            return JAMMED;
        }

        current_state = next_state;
        ++current_pos;

        if ( current_state->Accept() ) {
            last_accept_pos = current_pos;
            if ( current_state->IsTerminal() ) {
                current_state = nullptr;
                return JAMMED;
            }
        }
    }

    if ( eol ) {
        DFA_State* eol_state = current_state->Xtion(ecs[SYM_EOL], dfa);
        if ( eol_state && eol_state->Accept() )
            last_accept_pos = current_pos;
        current_state = nullptr;
        return JAMMED;
    }

    return ALIVE;
}

int Specific_RE_Matcher::LongestMatch(const u_char* bv, int n, bool bol, bool eol) {
    if ( ! dfa )
        // An empty pattern matches anything.
        return 0;

    // Use -1 to indicate no match.
    int last_accept = -1;
    DFA_State* d = dfa->StartState();

    if ( bol ) {
        d = d->Xtion(ecs[SYM_BOL], dfa);
        if ( ! d )
            return -1;
    }

    if ( d->Accept() ) // initial state or bol match (e.g, / */ or /^ ?/)
        last_accept = 0;

    for ( int i = 0; i < n; ++i ) {
        int ec = ecs[bv[i]];
        d = d->Xtion(ec, dfa);

        if ( ! d )
            break;

        if ( d->Accept() )
            last_accept = i + 1;
    }

    if ( d && eol ) {
        d = d->Xtion(ecs[SYM_EOL], dfa);
        if ( d && d->Accept() )
            return n;
    }

    return last_accept;
}

static RE_Matcher* matcher_merge(const RE_Matcher* re1, const RE_Matcher* re2, const char* merge_op) {
    const char* text1 = re1->PatternText();
    const char* text2 = re2->PatternText();

    size_t n = strlen(text1) + strlen(text2) + strlen(merge_op) + 32 /* slop */;

    std::string merge_text = util::fmt("(%s)%s(%s)", text1, merge_op, text2);
    RE_Matcher* merge = new RE_Matcher(merge_text.c_str());

    merge->Compile();

    return merge;
}

RE_Matcher* RE_Matcher_conjunction(const RE_Matcher* re1, const RE_Matcher* re2) { return matcher_merge(re1, re2, ""); }

RE_Matcher* RE_Matcher_disjunction(const RE_Matcher* re1, const RE_Matcher* re2) {
    return matcher_merge(re1, re2, "|");
}

} // namespace detail

RE_Matcher::RE_Matcher() {
    re_anywhere = new detail::Specific_RE_Matcher(detail::MATCH_ANYWHERE);
    re_exact = new detail::Specific_RE_Matcher(detail::MATCH_EXACTLY);
}

RE_Matcher::RE_Matcher(const char* pat) : orig_text(pat) {
    re_anywhere = new detail::Specific_RE_Matcher(detail::MATCH_ANYWHERE);
    re_exact = new detail::Specific_RE_Matcher(detail::MATCH_EXACTLY);

    AddPat(pat);
}

RE_Matcher::RE_Matcher(const char* exact_pat, const char* anywhere_pat) {
    re_anywhere = new detail::Specific_RE_Matcher(detail::MATCH_ANYWHERE);
    re_anywhere->SetPat(anywhere_pat);
    re_exact = new detail::Specific_RE_Matcher(detail::MATCH_EXACTLY);
    re_exact->SetPat(exact_pat);
}

RE_Matcher::~RE_Matcher() {
    delete re_anywhere;
    delete re_exact;
}

void RE_Matcher::AddPat(const char* new_pat) {
    re_anywhere->AddPat(new_pat);
    re_exact->AddPat(new_pat);
}

void RE_Matcher::MakeCaseInsensitive() {
    re_anywhere->MakeCaseInsensitive();
    re_exact->MakeCaseInsensitive();

    is_case_insensitive = true;
}

void RE_Matcher::MakeSingleLine() {
    re_anywhere->MakeSingleLine();
    re_exact->MakeSingleLine();

    is_single_line = true;
}

bool RE_Matcher::Compile(bool lazy) { return re_anywhere->Compile(lazy) && re_exact->Compile(lazy); }

TEST_SUITE("re_matcher") {
    TEST_CASE("simple_pattern") {
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

    TEST_CASE("case_insensitive_mode") {
        RE_Matcher match("[a-z]+");
        match.MakeCaseInsensitive();
        match.Compile();
        CHECK(strcmp(match.PatternText(), "(?i:^?([a-z]+)$?)") == 0);

        CHECK(match.MatchExactly("abcDEF"));
    }

    TEST_CASE("multi_pattern") {
        RE_Matcher match("[0-9]+");
        match.AddPat("[a-z]+");
        match.Compile();

        CHECK(strcmp(match.PatternText(), "(^?([0-9]+)$?)|(^?([a-z]+)$?)") == 0);

        CHECK(match.MatchExactly("abc"));
        CHECK(match.MatchExactly("123"));
        CHECK_FALSE(match.MatchExactly("abc123"));
    }

    TEST_CASE("modes_multi_pattern") {
        RE_Matcher match("[a-m]+");
        match.MakeCaseInsensitive();

        match.AddPat("[n-z]+");
        match.Compile();

        CHECK(strcmp(match.PatternText(), "((?i:^?([a-m]+)$?))|(^?([n-z]+)$?)") == 0);
        CHECK(match.MatchExactly("aBc"));
        CHECK(match.MatchExactly("nop"));
        CHECK_FALSE(match.MatchExactly("NoP"));
    }

    TEST_CASE("single_line_mode") {
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

    TEST_CASE("disjunction") {
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

    TEST_CASE("synerr causes Compile() to fail") {
        RE_Matcher match1("a{1,2}");
        CHECK(match1.Compile());

        RE_Matcher match2("a{6,5}");
        CHECK_FALSE(match2.Compile());

        RE_Matcher match3("a{1,a}");
        CHECK_FALSE(match3.Compile());

        RE_Matcher match4("a{1,2");
        CHECK_FALSE(match4.Compile());

        RE_Matcher match5("[1234");
        CHECK_FALSE(match5.Compile());

        RE_Matcher match6("a[1234}");
        CHECK_FALSE(match6.Compile());

        RE_Matcher match7("a\"b");
        CHECK_FALSE(match7.Compile());

        RE_Matcher match8("a\"b\"");
        CHECK(match8.Compile());

        RE_Matcher match9("a\\\"b");
        CHECK(match9.Compile());
    }
}

TEST_SUITE("streaming_re_matcher") {
    using detail::Streaming_RE_Matcher::ALIVE;
    using detail::Streaming_RE_Matcher::JAMMED;

    // easy "a"_b for a the uchar* type
    inline const u_char* operator""_b(const char* s, std::size_t) { return reinterpret_cast<const u_char*>(s); }

    auto make_streaming_matcher = [](const char* pat) {
        // Use MATCH_ANYWHERE so ^ or $ must be explicit in pattern when wanted.
        auto specific_re_matcher = std::make_unique<detail::Specific_RE_Matcher>(detail::MATCH_ANYWHERE);
        specific_re_matcher->AddPat(pat);
        REQUIRE(specific_re_matcher->Compile());
        auto streaming_re_matcher = std::make_unique<detail::Streaming_RE_Matcher>(specific_re_matcher.get());
        return std::pair{std::move(specific_re_matcher), std::move(streaming_re_matcher)};
    };

    TEST_CASE("feed eol jams") {
        auto [m, sm] = make_streaming_matcher("^ab$");
        auto r = sm->Feed("a"_b, 1, /*bol=*/true, /*eol=*/false);
        CHECK_EQ(r, ALIVE);
        CHECK_EQ(sm->Length(), 1);
        CHECK_EQ(sm->LastAccept(), -1);

        r = sm->Feed("b"_b, 1, /*bol=*/false, /*eol=*/false);
        CHECK_EQ(r, ALIVE);
        CHECK_EQ(sm->Length(), 2);
        CHECK_EQ(sm->LastAccept(), -1);

        // eol completes the match and jams.
        r = sm->Feed(""_b, 0, /*bol=*/false, /*eol=*/true);
        CHECK_EQ(r, JAMMED);
        CHECK_EQ(sm->Length(), 2);
        CHECK_EQ(sm->LastAccept(), 2);
    }

    TEST_CASE("feed longer match") {
        auto [m, sm] = make_streaming_matcher("^(ab)+");
        auto r = sm->Feed("ab"_b, 2, /*bol=*/true, /*eol=*/false);
        CHECK_EQ(r, ALIVE);
        CHECK_EQ(sm->Length(), 2);
        CHECK_EQ(sm->LastAccept(), 2);

        r = sm->Feed("a"_b, 1, /*bol=*/false, /*eol=*/false);
        CHECK_EQ(r, ALIVE);
        CHECK_EQ(sm->Length(), 3);
        CHECK_EQ(sm->LastAccept(), 2);

        r = sm->Feed("b"_b, 1, /*bol=*/false, /*eol=*/false);
        CHECK_EQ(r, ALIVE);
        CHECK_EQ(sm->Length(), 4);
        CHECK_EQ(sm->LastAccept(), 4);
    }

    TEST_CASE("feed longer match eol jams") {
        auto [m, sm] = make_streaming_matcher("^(ab)+");
        auto r = sm->Feed("ab"_b, 2, /*bol=*/true, /*eol=*/false);
        CHECK_EQ(r, ALIVE);
        CHECK_EQ(sm->Length(), 2);
        CHECK_EQ(sm->LastAccept(), 2);

        r = sm->Feed("a"_b, 1, /*bol=*/false, /*eol=*/false);
        CHECK_EQ(r, ALIVE);
        CHECK_EQ(sm->Length(), 3);
        CHECK_EQ(sm->LastAccept(), 2);

        r = sm->Feed("b"_b, 1, /*bol=*/false, /*eol=*/true);
        CHECK_EQ(r, JAMMED); // eol always jams
        CHECK_EQ(sm->Length(), 4);
        CHECK_EQ(sm->LastAccept(), 4);

        // once jammed, won't make progress anymore
        r = sm->Feed("ab"_b, 2, /*bol=*/false, /*eol=*/false);
        CHECK_EQ(r, JAMMED);
        CHECK_EQ(sm->Length(), 4);
        CHECK_EQ(sm->LastAccept(), 4);
    }

    TEST_CASE("feed bol without bol in pattern") {
        auto [m, sm] = make_streaming_matcher("ab+");
        auto r = sm->Feed("ab"_b, 2, /*bol=*/true, /*eol=*/false);
        CHECK_EQ(r, ALIVE);
        CHECK_EQ(sm->Length(), 2);
        CHECK_EQ(sm->LastAccept(), 2);
    }

    TEST_CASE("feed for first match jams after match") {
        auto [m, sm] = make_streaming_matcher("^ab+");
        auto r = sm->FeedForFirstMatch("abb"_b, 3, /*bol=*/true, /*eol=*/false);
        CHECK_EQ(r, JAMMED);
        CHECK_EQ(sm->Length(), 2); // only 2 bytes consumed, then jammed.
        CHECK_EQ(sm->LastAccept(), 2);
    }
}

} // namespace zeek
