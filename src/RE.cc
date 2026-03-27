// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/RE.h"

#include <cstdlib>
#include <cstring>
#include <string_view>
#include <utility>

#include "zeek/CCL.h"
#include "zeek/DFA.h"
#include "zeek/EquivClass.h"
#include "zeek/RegexBackend.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
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

static bool rust_stream_matchers_enabled() {
    static const bool enabled = std::getenv("ZEEK_DISABLE_RUST_STREAM_REGEX") == nullptr;
    return enabled;
}

static bool PatternUsesUnsupportedRustSyntax(const char* pat) {
    return pat && std::strchr(pat, '"') != nullptr;
}

static bool strip_wrapper(std::string_view text, std::string_view prefix, std::string_view suffix,
                          std::string_view* inner) {
    if ( ! text.starts_with(prefix) || ! text.ends_with(suffix) )
        return false;

    *inner = text.substr(prefix.size(), text.size() - prefix.size() - suffix.size());
    return true;
}

static std::string derive_rust_pattern_text(const char* exact_pat, const char* anywhere_pat) {
    if ( ! exact_pat || ! anywhere_pat )
        return {};

    std::string_view exact = exact_pat;
    std::string_view anywhere = anywhere_pat;
    std::vector<char> mode_wrappers;

    while ( true ) {
        if ( exact.starts_with("(?i:") && exact.ends_with(")") && anywhere.starts_with("(?i:") && anywhere.ends_with(")") ) {
            exact = exact.substr(4, exact.size() - 5);
            anywhere = anywhere.substr(4, anywhere.size() - 5);
            mode_wrappers.push_back('i');
            continue;
        }

        if ( exact.starts_with("(?s:") && exact.ends_with(")") && anywhere.starts_with("(?s:") && anywhere.ends_with(")") ) {
            exact = exact.substr(4, exact.size() - 5);
            anywhere = anywhere.substr(4, anywhere.size() - 5);
            mode_wrappers.push_back('s');
            continue;
        }

        break;
    }

    std::string_view exact_inner;
    std::string_view anywhere_inner;

    if ( ! strip_wrapper(exact, "^?(", ")$?", &exact_inner) )
        return {};

    if ( ! strip_wrapper(anywhere, "^?(.|\\n)*(", ")", &anywhere_inner) )
        return {};

    if ( exact_inner != anywhere_inner || exact_inner.find('"') != std::string_view::npos )
        return {};

    std::string result = util::fmt("(?:%.*s)", static_cast<int>(exact_inner.size()), exact_inner.data());

    for ( auto it = mode_wrappers.rbegin(); it != mode_wrappers.rend(); ++it )
        result = util::fmt("(?%c:%s)", *it, result.c_str());

    return result;
}

extern bool re_syntax_error;

Specific_RE_Matcher::Specific_RE_Matcher(match_type arg_mt, bool arg_multiline)
    : mt(arg_mt), multiline(arg_multiline), equiv_class(NUM_SYM) {
    any_ccl = nullptr;
    single_line_ccl = nullptr;
    dfa = nullptr;
    ecs = nullptr;
    accepted = new AcceptingSet();
}

Specific_RE_Matcher::~Specific_RE_Matcher() {
    for ( int i = 0; i < ccl_list.length(); ++i )
        delete ccl_list[i];

    ClearRustMatchers();
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
    ClearRustMatchers();
    AddRustPat(new_pat);

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

void Specific_RE_Matcher::AddRustPat(const char* new_pat) {
    if ( ! rust_backend_compatible )
        return;

    if ( PatternUsesUnsupportedRustSyntax(new_pat) ) {
        rust_backend_compatible = false;
        rust_pattern_text.clear();
        return;
    }

    if ( ! rust_pattern_text.empty() )
        rust_pattern_text = util::fmt("(?:%s)|(?:%s)", rust_pattern_text.c_str(), new_pat);
    else
        rust_pattern_text = util::fmt("(?:%s)", new_pat);
}

void Specific_RE_Matcher::ClearRustMatchers() {
    FreeRustRegexMatcher(rust_matcher);
    rust_matcher = nullptr;
    FreeRustRegexSetMatcher(rust_set_matcher);
    rust_set_matcher = nullptr;
    FreeRustRegexStreamMatcher(rust_stream_matcher);
    rust_stream_matcher = nullptr;
}

void Specific_RE_Matcher::MakeCaseInsensitive() {
    const char fmt[] = "(?i:%s)";
    pattern_text = util::fmt(fmt, pattern_text.c_str());

    if ( rust_backend_compatible && ! rust_pattern_text.empty() )
        rust_pattern_text = util::fmt(fmt, rust_pattern_text.c_str());

    ClearRustMatchers();
}

void Specific_RE_Matcher::MakeSingleLine() {
    const char fmt[] = "(?s:%s)";
    pattern_text = util::fmt(fmt, pattern_text.c_str());

    if ( rust_backend_compatible && ! rust_pattern_text.empty() )
        rust_pattern_text = util::fmt(fmt, rust_pattern_text.c_str());

    ClearRustMatchers();
}

void Specific_RE_Matcher::SetPat(const char* pat) {
    pattern_text = pat;
    rust_pattern_text.clear();
    rust_backend_compatible = false;
    ClearRustMatchers();
}

void Specific_RE_Matcher::SetRustPat(const char* pat) {
    rust_backend_compatible = pat && ! PatternUsesUnsupportedRustSyntax(pat);
    rust_pattern_text = rust_backend_compatible ? pat : "";
    ClearRustMatchers();
}

bool Specific_RE_Matcher::Compile(bool lazy) {
    if ( pattern_text.empty() )
        return false;

    ClearRustMatchers();
    if ( ! rust_pattern_text.empty() && RustRegexBackendAvailable() ) {
        rust_matcher = CompileRustRegexMatcher(rust_pattern_text);

        if ( rust_matcher ) {
            Unref(dfa);
            dfa = nullptr;
            ecs = nullptr;
            return true;
        }
    }

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

bool Specific_RE_Matcher::CompileSet(const string_list& set, const int_list& idx, const string_list* rust_set) {
    if ( (size_t)set.length() != idx.size() )
        reporter->InternalError("compileset: lengths of sets differ");

    if ( rust_set && (size_t)rust_set->length() != idx.size() )
        reporter->InternalError("compileset: lengths of Rust sets differ");

    rem = this;
    rust_pattern_text.clear();
    ClearRustMatchers();

    bool rust_set_compatible = true;

    if ( multiline ) {
        loop_over_list(set, i) {
            if ( PatternUsesUnsupportedRustSyntax(set[i]) ) {
                rust_set_compatible = false;
                break;
            }
        }
    }
    else if ( rust_set ) {
        loop_over_list((*rust_set), i) {
            if ( PatternUsesUnsupportedRustSyntax((*rust_set)[i]) ) {
                rust_set_compatible = false;
                break;
            }
        }
    }
    else
        rust_set_compatible = false;

    if ( rust_set_compatible && RustRegexBackendAvailable() ) {
        std::vector<const char*> rust_patterns;
        std::vector<std::intptr_t> rust_ids;
        rust_patterns.reserve(multiline ? set.length() : rust_set->length());
        rust_ids.reserve(idx.size());

        if ( multiline ) {
            loop_over_list(set, i) {
                rust_patterns.push_back(set[i]);
                rust_ids.push_back(idx[i]);
            }

            rust_stream_matcher = CompileRustRegexStreamMatcher(rust_patterns, rust_ids, true);

            if ( rust_stream_matcher )
                return true;
        }
        else {
            loop_over_list((*rust_set), i) {
                rust_patterns.push_back((*rust_set)[i]);
                rust_ids.push_back(idx[i]);
            }

            rust_set_matcher = CompileRustRegexSetMatcher(rust_patterns, rust_ids);

            if ( rust_set_matcher )
                return true;
        }
    }

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
    if ( matches && rust_set_matcher ) {
        const auto before = matches->size();
        RustRegexSetMatcherAppendMatches(rust_set_matcher, reinterpret_cast<const uint8_t*>(bv), n, *matches);
        return matches->size() != before;
    }

    if ( ! matches && rust_set_matcher )
        return RustRegexSetMatcherMatchAny(rust_set_matcher, reinterpret_cast<const uint8_t*>(bv), n);

    if ( ! matches && rust_matcher )
        return RustRegexMatcherMatchAll(rust_matcher, reinterpret_cast<const uint8_t*>(bv), n);

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
    if ( rust_matcher )
        return RustRegexMatcherFindEnd(rust_matcher, reinterpret_cast<const uint8_t*>(bv), n);

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

void Specific_RE_Matcher::Dump(FILE* f) {
    if ( dfa )
        dfa->Dump(f);
}

inline void RE_Match_State::AddMatches(const AcceptingSet& as, MatchPos position) {
    using am_idx = std::pair<AcceptIdx, MatchPos>;

    for ( const auto& entry : as )
        accepted_matches.insert(am_idx(entry, position));
}

RE_Match_State::RE_Match_State(Specific_RE_Matcher* matcher) {
    dfa = matcher->DFA() ? matcher->DFA() : nullptr;
    ecs = dfa ? matcher->EC()->EquivClasses() : nullptr;
    current_pos = -1;
    current_state = nullptr;
    rust_stream_matcher = rust_stream_matchers_enabled() ? matcher->RustStreamMatcher() : nullptr;
    rust_stream_state = rust_stream_matcher ? CreateRustRegexStreamState(rust_stream_matcher) : nullptr;
}

RE_Match_State::~RE_Match_State() { FreeRustRegexStreamState(rust_stream_state); }

void RE_Match_State::Clear() {
    current_pos = -1;
    current_state = nullptr;
    accepted_matches.clear();

    if ( rust_stream_matcher ) {
        FreeRustRegexStreamState(rust_stream_state);
        rust_stream_state = CreateRustRegexStreamState(rust_stream_matcher);
    }
}

bool RE_Match_State::Match(const u_char* bv, int n, bool bol, bool eol, bool clear) {
    if ( rust_stream_matcher && rust_stream_state ) {
        if ( clear ) {
            FreeRustRegexStreamState(rust_stream_state);
            rust_stream_state = CreateRustRegexStreamState(rust_stream_matcher);
            current_pos = -1;
            current_state = nullptr;
        }

        if ( ! rust_stream_state )
            return false;

        const auto old_matches = accepted_matches.size();
        std::vector<std::pair<AcceptIdx, uint64_t>> matches;
        RustRegexStreamStateAppendMatches(rust_stream_matcher, rust_stream_state, reinterpret_cast<const uint8_t*>(bv),
                                          n, bol, eol, run_state::detail::bare_mode, matches);

        for ( const auto& [accept_idx, position] : matches )
            accepted_matches.emplace(accept_idx, position);

        return accepted_matches.size() != old_matches;
    }

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

int Specific_RE_Matcher::LongestMatch(const u_char* bv, int n, bool bol, bool eol) {
    if ( rust_matcher )
        return RustRegexMatcherLongestPrefix(rust_matcher, reinterpret_cast<const uint8_t*>(bv), n, bol, eol);

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

    const char* rust_text1 = re1->RustPatternText();
    const char* rust_text2 = re2->RustPatternText();

    if ( rust_text1 && rust_text1[0] && rust_text2 && rust_text2[0] )
        merge->SetRustPat(util::fmt("(%s)%s(%s)", rust_text1, merge_op, rust_text2));

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

RE_Matcher::RE_Matcher(const char* exact_pat, const char* anywhere_pat)
    : RE_Matcher(exact_pat, anywhere_pat, nullptr) {}

RE_Matcher::RE_Matcher(const char* exact_pat, const char* anywhere_pat, const char* rust_pat) {
    const auto derived_rust_pat =
        (! rust_pat || ! rust_pat[0]) ? detail::derive_rust_pattern_text(exact_pat, anywhere_pat) : std::string{};
    const char* effective_rust_pat = rust_pat && rust_pat[0] ? rust_pat :
                                     (derived_rust_pat.empty() ? nullptr : derived_rust_pat.c_str());

    re_anywhere = new detail::Specific_RE_Matcher(detail::MATCH_ANYWHERE);
    re_anywhere->SetPat(anywhere_pat);
    re_anywhere->SetRustPat(effective_rust_pat);
    re_exact = new detail::Specific_RE_Matcher(detail::MATCH_EXACTLY);
    re_exact->SetPat(exact_pat);
    re_exact->SetRustPat(effective_rust_pat);
}

RE_Matcher::~RE_Matcher() {
    delete re_anywhere;
    delete re_exact;
}

void RE_Matcher::AddPat(const char* new_pat) {
    re_anywhere->AddPat(new_pat);
    re_exact->AddPat(new_pat);
}

void RE_Matcher::SetRustPat(const char* pat) {
    re_anywhere->SetRustPat(pat);
    re_exact->SetRustPat(pat);
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

    TEST_CASE("matcher merge preserves Rust pattern text") {
        RE_Matcher match1("foo");
        match1.MakeCaseInsensitive();
        REQUIRE(match1.Compile());

        RE_Matcher match2("bar");
        REQUIRE(match2.Compile());

        auto dj = detail::RE_Matcher_disjunction(&match1, &match2);
        CHECK(std::string(dj->RustPatternText()) == "((?i:(?:foo)))|((?:bar))");
        CHECK(dj->MatchExactly("FoO"));
        CHECK(dj->MatchExactly("bar"));
        delete dj;

        auto cj = detail::RE_Matcher_conjunction(&match1, &match2);
        CHECK(std::string(cj->RustPatternText()) == "((?i:(?:foo)))((?:bar))");
        CHECK(cj->MatchExactly("FoObar"));
        delete cj;
    }

    TEST_CASE("reconstructed matchers derive Rust pattern text from Zeek wrappers") {
        RE_Matcher original("foo");
        original.MakeCaseInsensitive();
        REQUIRE(original.Compile());

        RE_Matcher reconstructed(original.PatternText(), original.AnywherePatternText());
        REQUIRE(reconstructed.Compile());

        CHECK(std::string(reconstructed.RustPatternText()) == "(?i:(?:foo))");
        CHECK(reconstructed.MatchExactly("FoO"));
    }

    TEST_CASE("rust-compatible matchers do not require a legacy dfa") {
        RE_Matcher match("foo");
        REQUIRE(match.Compile());
        CHECK(match.MatchExactly("foo"));

        if ( detail::RustRegexBackendAvailable() )
            CHECK(match.DFA() == nullptr);
    }

    TEST_CASE("rust-compatible exact match sets do not require a legacy dfa") {
        RE_Matcher foo("foo");
        RE_Matcher dots("f.o");
        REQUIRE(foo.Compile());
        REQUIRE(dots.Compile());

        detail::string_list patterns;
        detail::string_list rust_patterns;
        detail::int_list ids = {1, 2};

        patterns.push_back(const_cast<char*>(foo.PatternText()));
        patterns.push_back(const_cast<char*>(dots.PatternText()));
        rust_patterns.push_back(const_cast<char*>(foo.RustPatternText()));
        rust_patterns.push_back(const_cast<char*>(dots.RustPatternText()));

        detail::Specific_RE_Matcher set_matcher(detail::MATCH_EXACTLY);
        REQUIRE(set_matcher.CompileSet(patterns, ids, &rust_patterns));

        std::vector<detail::AcceptIdx> matches;
        CHECK(set_matcher.MatchSet("foo", matches));
        CHECK(matches.size() == 2);

        if ( detail::RustRegexBackendAvailable() )
            CHECK(set_matcher.DFA() == nullptr);
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

} // namespace zeek
