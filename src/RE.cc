// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/RE.h"

#include <cstdint>
#include <cstring>
#include <string_view>
#include <utility>

#include "zeek/NetVar.h"
#include "zeek/RegexBackend.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/ZeekString.h"

#include "zeek/3rdparty/doctest.h"

namespace zeek {
namespace detail {

Specific_RE_Matcher::Specific_RE_Matcher(match_type arg_mt, bool arg_multiline)
    : Specific_RE_Matcher(arg_mt, arg_multiline, std::make_shared<MatcherPatternState>()) {}

Specific_RE_Matcher::Specific_RE_Matcher(match_type arg_mt, bool arg_multiline,
                                         std::shared_ptr<MatcherPatternState> arg_pattern_state)
    : mt(arg_mt),
      multiline(arg_multiline),
      pattern_state(arg_pattern_state ? std::move(arg_pattern_state) : std::make_shared<MatcherPatternState>()) {}

Specific_RE_Matcher::~Specific_RE_Matcher() { ClearRustMatchers(); }

void Specific_RE_Matcher::AddPat(const char* new_pat) {
    ClearRustMatchers();
    AddExactPat(new_pat);
    ClearDerivedTextCaches();
}

void Specific_RE_Matcher::AddExactPat(const char* new_pat) {
    AppendPat(&pattern_state->exact_pattern_text, new_pat, "^?(%s)$?", "(%s)|(^?(%s)$?)");
}

void Specific_RE_Matcher::AppendPat(std::string* target, const char* new_pat, const char* orig_fmt,
                                    const char* app_fmt) {
    if ( ! target )
        return;

    if ( ! target->empty() )
        *target = util::fmt(app_fmt, target->c_str(), new_pat);
    else
        *target = util::fmt(orig_fmt, new_pat);
}

void Specific_RE_Matcher::ClearDerivedTextCaches() {
    pattern_state->anywhere_pattern_text.clear();
    pattern_state->rust_pattern_text.clear();
    pattern_state->anywhere_pattern_text_cached = false;
    pattern_state->rust_pattern_text_cached = false;
}

void Specific_RE_Matcher::ClearRustMatchers() {
    rust_matcher.reset();
    rust_set_matcher.reset();
    rust_stream_matcher.reset();
}

const char* Specific_RE_Matcher::PatternText() const {
    if ( mt == MATCH_EXACTLY )
        return pattern_state->exact_pattern_text.c_str();

    if ( pattern_state->anywhere_pattern_text_cached )
        return pattern_state->anywhere_pattern_text.c_str();

    pattern_state->anywhere_pattern_text =
        pattern_state->exact_pattern_text.empty() ?
            "" :
            DeriveAnywherePatternFromExact(pattern_state->exact_pattern_text.c_str());

    if ( pattern_state->anywhere_pattern_text.empty() && ! pattern_state->exact_pattern_text.empty() )
        pattern_state->anywhere_pattern_text = pattern_state->exact_pattern_text;

    pattern_state->anywhere_pattern_text_cached = true;
    return pattern_state->anywhere_pattern_text.c_str();
}

const char* Specific_RE_Matcher::RustPatternText() const {
    if ( pattern_state->rust_pattern_text_cached )
        return pattern_state->rust_pattern_text.c_str();

    pattern_state->rust_pattern_text.clear();

    if ( ! pattern_state->exact_pattern_text.empty() )
        pattern_state->rust_pattern_text = DeriveRustPatternFromExact(pattern_state->exact_pattern_text.c_str());

    if ( pattern_state->rust_pattern_text.empty() )
        pattern_state->rust_pattern_text = pattern_state->rust_pattern_fallback_text;

    pattern_state->rust_pattern_text_cached = true;
    return pattern_state->rust_pattern_text.c_str();
}

void Specific_RE_Matcher::MakeCaseInsensitive() {
    const char fmt[] = "(?i:%s)";
    pattern_state->exact_pattern_text = util::fmt(fmt, pattern_state->exact_pattern_text.c_str());

    ClearDerivedTextCaches();
    ClearRustMatchers();
}

void Specific_RE_Matcher::MakeSingleLine() {
    const char fmt[] = "(?s:%s)";
    pattern_state->exact_pattern_text = util::fmt(fmt, pattern_state->exact_pattern_text.c_str());

    ClearDerivedTextCaches();
    ClearRustMatchers();
}

void Specific_RE_Matcher::SetPat(const char* pat) {
    pattern_state->exact_pattern_text = pat ? pat : "";
    pattern_state->rust_pattern_fallback_text.clear();
    ClearDerivedTextCaches();
    ClearRustMatchers();
}

void Specific_RE_Matcher::SetRustPat(const char* pat) {
    pattern_state->rust_pattern_fallback_text = pat ? pat : "";
    pattern_state->rust_pattern_text.clear();
    pattern_state->rust_pattern_text_cached = false;
    ClearRustMatchers();
}

bool Specific_RE_Matcher::Compile(bool lazy) {
    if ( pattern_state->exact_pattern_text.empty() )
        return false;

    ClearRustMatchers();

    rust_matcher = CompileRustRegexMatcherFromExact(pattern_state->exact_pattern_text);

    if ( ! rust_matcher && ! pattern_state->rust_pattern_fallback_text.empty() )
        rust_matcher = CompileRustRegexMatcher(pattern_state->rust_pattern_fallback_text);

    if ( ! rust_matcher ) {
        reporter->Error("error compiling pattern /%s/", PatternText());
        return false;
    }

    return true;
}

bool Specific_RE_Matcher::CompileSet(const string_list& set, const int_list& idx, const string_list* rust_set) {
    if ( static_cast<size_t>(set.length()) != idx.size() )
        reporter->InternalError("compileset: lengths of sets differ");

    if ( rust_set && (size_t)rust_set->length() != idx.size() )
        reporter->InternalError("compileset: lengths of Rust sets differ");

    ClearDerivedTextCaches();
    ClearRustMatchers();

    std::vector<const char*> compile_patterns;
    std::vector<std::intptr_t> rust_ids;
    compile_patterns.reserve(multiline ? set.length() : (rust_set ? rust_set->length() : set.length()));
    rust_ids.reserve(idx.size());

    for ( size_t i = 0; i < idx.size(); ++i )
        rust_ids.push_back(idx[i]);

    if ( multiline ) {
        loop_over_list(set, i) { compile_patterns.push_back(set[i]); }
    }
    else if ( rust_set ) {
        loop_over_list((*rust_set), i) { compile_patterns.push_back((*rust_set)[i]); }
    }
    else {
        loop_over_list(set, i) { compile_patterns.push_back(set[i]); }
    }

    if ( multiline ) {
        rust_stream_matcher =
            CompileRustRegexStreamMatcherFromZeek(compile_patterns, rust_ids, true, sig_rust_regex_cache_size);

        if ( rust_stream_matcher )
            return true;
    }
    else if ( rust_set ) {
        rust_set_matcher = CompileRustRegexSetMatcher(compile_patterns, rust_ids);

        if ( rust_set_matcher )
            return true;
    }
    else {
        rust_set_matcher = CompileRustRegexSetMatcherFromExact(compile_patterns, rust_ids);

        if ( rust_set_matcher )
            return true;
    }

    for ( size_t i = 0; i < compile_patterns.size(); ++i ) {
        std::vector<const char*> single_pattern = {compile_patterns[i]};
        std::vector<std::intptr_t> single_id = {rust_ids[i]};

        if ( multiline ) {
            auto matcher =
                CompileRustRegexStreamMatcherFromZeek(single_pattern, single_id, true, sig_rust_regex_cache_size);

            if ( matcher )
                continue;
        }
        else if ( rust_set ) {
            auto matcher = CompileRustRegexSetMatcher(single_pattern, single_id);

            if ( matcher )
                continue;
        }
        else {
            auto matcher = CompileRustRegexSetMatcherFromExact(single_pattern, single_id);

            if ( matcher )
                continue;
        }

        reporter->Error("error compiling pattern /%s/", set[static_cast<int>(i)]);
        return false;
    }

    reporter->Error("error compiling pattern /%s/", set.length() > 0 ? set[0] : "<empty>");
    return false;
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

    // Historically, a matcher with no compiled backend only matches the
    // empty input exactly.
    return n == 0;
}

int Specific_RE_Matcher::Match(const u_char* bv, int n) {
    if ( rust_matcher )
        return RustRegexMatcherFindEnd(rust_matcher, reinterpret_cast<const uint8_t*>(bv), n);

    // Historically, a matcher with no compiled backend behaves like an empty
    // pattern for "match anywhere" queries.
    return 1;
}

unsigned int Specific_RE_Matcher::NumStates() const { return 0; }

void Specific_RE_Matcher::GetStats(RegexStats* stats) const {
    if ( ! stats )
        return;

    *stats = {};

    if ( rust_matcher )
        stats->patterns = 1;

    if ( rust_set_matcher )
        stats->patterns = RustRegexSetMatcherPatternLen(rust_set_matcher);

    if ( rust_stream_matcher ) {
        stats->patterns = RustRegexStreamMatcherPatternLen(rust_stream_matcher);
        stats->stream_matchers = 1;
        stats->cache_bytes = RustRegexStreamMatcherCacheBytes(rust_stream_matcher);
        stats->cache_clears = RustRegexStreamMatcherCacheClears(rust_stream_matcher);
    }
}

void Specific_RE_Matcher::Dump(FILE* /* f */) {}

RE_Match_State::RE_Match_State(Specific_RE_Matcher* matcher) : current_pos(-1) {
    const auto& stream_matcher = matcher->RustStreamMatcher();
    rust_stream_matcher = stream_matcher ? &stream_matcher : nullptr;
    rust_stream_state =
        rust_stream_matcher ? CreateRustRegexStreamState(*rust_stream_matcher) : RustRegexStreamStateHandle{};
}

RE_Match_State::~RE_Match_State() = default;

void RE_Match_State::Clear() {
    current_pos = -1;
    accepted_matches.clear();

    if ( rust_stream_matcher )
        rust_stream_state = CreateRustRegexStreamState(*rust_stream_matcher);
}

bool RE_Match_State::Match(const u_char* bv, int n, bool bol, bool eol, bool clear) {
    if ( rust_stream_matcher && rust_stream_state ) {
        if ( clear ) {
            rust_stream_state = CreateRustRegexStreamState(*rust_stream_matcher);
            current_pos = -1;
        }

        if ( ! rust_stream_state )
            return false;

        const auto old_matches = accepted_matches.size();
        std::vector<std::pair<AcceptIdx, uint64_t>> matches;
        RustRegexStreamStateAppendMatches(*rust_stream_matcher, rust_stream_state, reinterpret_cast<const uint8_t*>(bv),
                                          n, bol, eol, run_state::detail::bare_mode, matches);

        for ( const auto& [accept_idx, position] : matches )
            accepted_matches.emplace(accept_idx, position);

        return accepted_matches.size() != old_matches;
    }

    return false;
}

int Specific_RE_Matcher::LongestMatch(const u_char* bv, int n, bool bol, bool eol) {
    if ( rust_matcher )
        return RustRegexMatcherLongestPrefix(rust_matcher, reinterpret_cast<const uint8_t*>(bv), n, bol, eol);

    // Historically, a matcher with no compiled backend behaves like an empty
    // pattern for longest-prefix queries.
    return 0;
}

static RE_Matcher* matcher_merge(const RE_Matcher* re1, const RE_Matcher* re2, const char* merge_op) {
    const char* text1 = re1->PatternText();
    const char* text2 = re2->PatternText();

    std::string merge_text = util::fmt("(%s)%s(%s)", text1, merge_op, text2);
    const char* rust_text1 = re1->RustPatternText();
    const char* rust_text2 = re2->RustPatternText();
    std::string merge_rust_text;

    if ( rust_text1 && rust_text1[0] && rust_text2 && rust_text2[0] )
        merge_rust_text = util::fmt("(%s)%s(%s)", rust_text1, merge_op, rust_text2);

    auto* merge = RE_Matcher::Reconstruct(merge_text.c_str());

    if ( merge && merge->Compile() )
        return merge;

    delete merge;
    merge = RE_Matcher::Reconstruct(merge_text.c_str(), merge_rust_text.empty() ? nullptr : merge_rust_text.c_str());

    if ( merge )
        merge->Compile();

    return merge;
}

RE_Matcher* RE_Matcher_conjunction(const RE_Matcher* re1, const RE_Matcher* re2) { return matcher_merge(re1, re2, ""); }

RE_Matcher* RE_Matcher_disjunction(const RE_Matcher* re1, const RE_Matcher* re2) {
    return matcher_merge(re1, re2, "|");
}

} // namespace detail

RE_Matcher::RE_Matcher() {
    auto shared_pattern_state = std::make_shared<detail::MatcherPatternState>();
    re_anywhere = new detail::Specific_RE_Matcher(detail::MATCH_ANYWHERE, false, shared_pattern_state);
    re_exact = new detail::Specific_RE_Matcher(detail::MATCH_EXACTLY, false, std::move(shared_pattern_state));
}

RE_Matcher::RE_Matcher(const char* pat) : orig_text(pat) {
    auto shared_pattern_state = std::make_shared<detail::MatcherPatternState>();
    re_anywhere = new detail::Specific_RE_Matcher(detail::MATCH_ANYWHERE, false, shared_pattern_state);
    re_exact = new detail::Specific_RE_Matcher(detail::MATCH_EXACTLY, false, std::move(shared_pattern_state));

    AddPat(pat);
}

RE_Matcher* RE_Matcher::Reconstruct(const char* exact_pat, const char* rust_pat) {
    if ( ! exact_pat )
        return nullptr;

    auto* re = new RE_Matcher();
    re->re_exact->SetPat(exact_pat);

    if ( rust_pat && rust_pat[0] )
        re->re_exact->SetRustPat(rust_pat);

    return re;
}

RE_Matcher::~RE_Matcher() {
    delete re_anywhere;
    delete re_exact;
}

void RE_Matcher::AddPat(const char* new_pat) {
    re_exact->AddPat(new_pat);
    re_anywhere->ClearRustMatchers();
}

void RE_Matcher::SetRustPat(const char* pat) {
    re_exact->SetRustPat(pat);
    re_anywhere->ClearRustMatchers();
}

void RE_Matcher::MakeCaseInsensitive() {
    re_exact->MakeCaseInsensitive();
    re_anywhere->ClearRustMatchers();

    is_case_insensitive = true;
}

void RE_Matcher::MakeSingleLine() {
    re_exact->MakeSingleLine();
    re_anywhere->ClearRustMatchers();

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

    TEST_CASE("exact matches honor full-string alternations") {
        RE_Matcher match("[0-9]{1}|[0-9]{2}|0[0-9]{2}|1[0-9]{2}|2[0-4][0-9]|25[0-5]");
        REQUIRE(match.Compile());

        CHECK(match.MatchExactly("9"));
        CHECK(match.MatchExactly("99"));
        CHECK(match.MatchExactly("192"));
        CHECK(match.MatchExactly("255"));
        CHECK_FALSE(match.MatchExactly("256"));
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
        CHECK(cj->MatchExactly("fOObar"));
        delete cj;
    }

    TEST_CASE("reconstructed matchers derive Rust pattern text from Zeek wrappers") {
        RE_Matcher original("foo");
        original.MakeCaseInsensitive();
        REQUIRE(original.Compile());

        auto* reconstructed = RE_Matcher::Reconstruct(original.PatternText());
        REQUIRE(reconstructed != nullptr);
        REQUIRE(reconstructed->Compile());

        CHECK(strcmp(reconstructed->AnywherePatternText(), original.AnywherePatternText()) == 0);
        CHECK(std::string(reconstructed->RustPatternText()) == "(?i:(?:foo))");
        CHECK(reconstructed->MatchExactly("FoO"));
        delete reconstructed;
    }

    TEST_CASE("reconstructed merged matchers derive Rust pattern text from Zeek wrappers") {
        RE_Matcher match1("foo");
        match1.MakeCaseInsensitive();
        REQUIRE(match1.Compile());

        RE_Matcher match2("bar");
        REQUIRE(match2.Compile());

        auto merged = detail::RE_Matcher_disjunction(&match1, &match2);
        auto* reconstructed = RE_Matcher::Reconstruct(merged->PatternText());
        REQUIRE(reconstructed != nullptr);
        REQUIRE(reconstructed->Compile());

        CHECK(strcmp(reconstructed->AnywherePatternText(), merged->AnywherePatternText()) == 0);
        CHECK_FALSE(std::string(reconstructed->RustPatternText()).empty());
        CHECK(reconstructed->MatchExactly("FoO"));
        CHECK(reconstructed->MatchExactly("bar"));

        delete reconstructed;
        delete merged;
    }

    TEST_CASE("quoted regex strings stay case-sensitive inside /i") {
        RE_Matcher match("\"fOO\"");
        match.MakeCaseInsensitive();
        REQUIRE(match.Compile());

        CHECK(std::string(match.RustPatternText()).find("(?-i:") != std::string::npos);
        CHECK(match.MatchExactly("fOO"));
        CHECK_FALSE(match.MatchExactly("FoO"));
        CHECK(match.MatchAnywhere("xfOObar") != 0);
        CHECK(match.MatchAnywhere("xFoObar") == 0);
    }

    TEST_CASE("quoted regex strings reconstruct onto the Rust path") {
        RE_Matcher original("\"fOO\"");
        original.MakeCaseInsensitive();
        REQUIRE(original.Compile());

        auto* reconstructed = RE_Matcher::Reconstruct(original.PatternText());
        REQUIRE(reconstructed != nullptr);
        REQUIRE(reconstructed->Compile());

        CHECK(std::string(reconstructed->RustPatternText()).find("(?-i:") != std::string::npos);
        CHECK(reconstructed->MatchExactly("fOO"));
        CHECK_FALSE(reconstructed->MatchExactly("FoO"));
        delete reconstructed;
    }

    TEST_CASE("literal bracket character classes normalize onto the Rust path") {
        RE_Matcher match("[[]");
        REQUIRE(match.Compile());

        CHECK(std::string(match.RustPatternText()).find("\\x5b") != std::string::npos);
        CHECK(match.MatchExactly("["));
    }

    TEST_CASE("rust-compatible matchers do not require a legacy dfa") {
        RE_Matcher match("foo");
        REQUIRE(match.Compile());
        CHECK(match.MatchExactly("foo"));
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
    }

    TEST_CASE("exact match sets derive Rust patterns from Zeek wrapper text") {
        RE_Matcher foo("foo");
        foo.MakeCaseInsensitive();
        RE_Matcher bar("bar");
        REQUIRE(foo.Compile());
        REQUIRE(bar.Compile());

        detail::string_list patterns;
        detail::int_list ids = {1, 2};

        patterns.push_back(const_cast<char*>(foo.PatternText()));
        patterns.push_back(const_cast<char*>(bar.PatternText()));

        detail::Specific_RE_Matcher set_matcher(detail::MATCH_EXACTLY);
        REQUIRE(set_matcher.CompileSet(patterns, ids));

        std::vector<detail::AcceptIdx> matches;
        CHECK(set_matcher.MatchSet("FoO", matches));
        CHECK(matches.size() == 1);
        CHECK(matches[0] == 1);

        matches.clear();
        CHECK(set_matcher.MatchSet("bar", matches));
        CHECK(matches.size() == 1);
        CHECK(matches[0] == 2);
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
