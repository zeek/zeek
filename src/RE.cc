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

static bool is_octal_digit(char c) { return c >= '0' && c <= '7'; }

static bool is_hex_digit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static uint8_t parse_hex_digit(char c) {
    if ( c >= '0' && c <= '9' )
        return static_cast<uint8_t>(c - '0');

    if ( c >= 'a' && c <= 'f' )
        return static_cast<uint8_t>(10 + c - 'a');

    return static_cast<uint8_t>(10 + c - 'A');
}

static void append_hex_escaped_byte(std::string* normalized, uint8_t byte) {
    static constexpr char hex[] = "0123456789abcdef";

    normalized->push_back('\\');
    normalized->push_back('x');
    normalized->push_back(hex[byte >> 4]);
    normalized->push_back(hex[byte & 0x0f]);
}

static bool consume_zeek_escape(std::string_view pattern, size_t* pos, uint8_t* byte) {
    if ( *pos + 1 >= pattern.size() || pattern[*pos + 1] == '\n' )
        return false;

    const auto next = pattern[*pos + 1];

    if ( next == 'x' ) {
        if ( *pos + 3 >= pattern.size() || ! is_hex_digit(pattern[*pos + 2]) || ! is_hex_digit(pattern[*pos + 3]) )
            return false;

        *byte = static_cast<uint8_t>((parse_hex_digit(pattern[*pos + 2]) << 4) | parse_hex_digit(pattern[*pos + 3]));
        *pos += 4;
        return true;
    }

    if ( is_octal_digit(next) ) {
        size_t end = *pos + 1;

        while ( end < pattern.size() && is_octal_digit(pattern[end]) )
            ++end;

        int value = 0;
        size_t digits = end - (*pos + 1);

        if ( digits > 3 )
            digits = 3;

        for ( size_t i = 0; i < digits; ++i )
            value = (value << 3) | (pattern[*pos + 1 + i] - '0');

        *byte = static_cast<uint8_t>(value);
        *pos = end;
        return true;
    }

    switch ( next ) {
        case 'b': *byte = '\b'; break;
        case 'f': *byte = '\f'; break;
        case 'n': *byte = '\n'; break;
        case 'r': *byte = '\r'; break;
        case 't': *byte = '\t'; break;
        case 'a': *byte = '\a'; break;
        case 'v': *byte = '\v'; break;
        default: *byte = static_cast<uint8_t>(next); break;
    }

    *pos += 2;
    return true;
}

static bool normalize_zeek_pattern_for_rust(std::string_view pattern, std::string* normalized) {
    normalized->clear();
    normalized->reserve(pattern.size() + 16);

    bool in_class = false;
    bool in_quote = false;

    // Zeek's quoted regex strings are frontend sugar for literal byte sequences
    // that stay case-sensitive inside a larger /.../i expression.
    for ( size_t pos = 0; pos < pattern.size(); ) {
        const auto c = pattern[pos];

        if ( in_quote ) {
            if ( c == '"' ) {
                normalized->push_back(')');
                in_quote = false;
                ++pos;
                continue;
            }

            uint8_t byte = 0;

            if ( c == '\\' ) {
                if ( ! consume_zeek_escape(pattern, &pos, &byte) )
                    return false;
            }
            else if ( c == '\n' )
                return false;
            else {
                byte = static_cast<uint8_t>(c);
                ++pos;
            }

            append_hex_escaped_byte(normalized, byte);
            continue;
        }

        if ( c == '\\' ) {
            uint8_t byte = 0;

            // Zeek's regex scanner expands escapes into literal bytes rather
            // than preserving them as regex operators, so we encode the byte
            // value directly for the Rust backend.
            if ( ! consume_zeek_escape(pattern, &pos, &byte) )
                return false;

            append_hex_escaped_byte(normalized, byte);
            continue;
        }

        if ( c == '[' && pos + 2 < pattern.size() && pattern[pos + 1] == '[' && pattern[pos + 2] == ']' ) {
            append_hex_escaped_byte(normalized, '[');
            pos += 3;
            continue;
        }

        if ( c == '[' && pos + 2 < pattern.size() && pattern[pos + 1] == ']' && pattern[pos + 2] == ']' ) {
            append_hex_escaped_byte(normalized, ']');
            pos += 3;
            continue;
        }

        if ( c == '[' ) {
            in_class = true;
            normalized->push_back(c);
            ++pos;
            continue;
        }

        if ( c == ']' && in_class ) {
            in_class = false;
            normalized->push_back(c);
            ++pos;
            continue;
        }

        if ( c == '"' && ! in_class ) {
            normalized->append("(?-i:");
            in_quote = true;
            ++pos;
            continue;
        }

        normalized->push_back(c);
        ++pos;
    }

    return ! in_quote;
}

static bool strip_wrapper(std::string_view text, std::string_view prefix, std::string_view suffix,
                          std::string_view* inner) {
    if ( ! text.starts_with(prefix) || ! text.ends_with(suffix) )
        return false;

    *inner = text.substr(prefix.size(), text.size() - prefix.size() - suffix.size());
    return true;
}

static size_t find_matching_paren(std::string_view text, size_t start) {
    if ( start >= text.size() || text[start] != '(' )
        return std::string_view::npos;

    size_t depth = 0;
    bool escaped = false;
    bool in_class = false;

    for ( size_t i = start; i < text.size(); ++i ) {
        const auto c = text[i];

        if ( escaped ) {
            escaped = false;
            continue;
        }

        if ( c == '\\' ) {
            escaped = true;
            continue;
        }

        if ( in_class ) {
            if ( c == ']' )
                in_class = false;

            continue;
        }

        if ( c == '[' ) {
            in_class = true;
            continue;
        }

        if ( c == '(' ) {
            ++depth;
            continue;
        }

        if ( c != ')' )
            continue;

        if ( depth == 0 )
            return std::string_view::npos;

        --depth;

        if ( depth == 0 )
            return i;
    }

    return std::string_view::npos;
}

static bool split_top_level_wrapped_operands(std::string_view text, std::vector<std::string_view>* parts, char* op) {
    parts->clear();
    *op = '\0';

    size_t pos = 0;

    while ( pos < text.size() ) {
        if ( text[pos] != '(' )
            return false;

        const auto end = find_matching_paren(text, pos);

        if ( end == std::string_view::npos )
            return false;

        parts->push_back(text.substr(pos + 1, end - pos - 1));
        pos = end + 1;

        if ( pos == text.size() )
            return ! parts->empty();

        if ( text[pos] == '|' ) {
            if ( *op == '\0' )
                *op = '|';
            else if ( *op != '|' )
                return false;

            ++pos;
            continue;
        }

        if ( text[pos] == '(' ) {
            if ( *op == '\0' )
                *op = '+';
            else if ( *op != '+' )
                return false;

            continue;
        }

        return false;
    }

    return ! parts->empty();
}

static std::string derive_rust_pattern_from_exact(std::string_view exact) {
    std::vector<char> mode_wrappers;

    while ( true ) {
        if ( exact.starts_with("(?i:") && exact.ends_with(")") ) {
            exact = exact.substr(4, exact.size() - 5);
            mode_wrappers.push_back('i');
            continue;
        }

        if ( exact.starts_with("(?s:") && exact.ends_with(")") ) {
            exact = exact.substr(4, exact.size() - 5);
            mode_wrappers.push_back('s');
            continue;
        }

        break;
    }

    std::string_view exact_inner;

    std::string result;

    if ( strip_wrapper(exact, "^?(", ")$?", &exact_inner) ) {
        std::string normalized_exact_inner;

        if ( ! normalize_zeek_pattern_for_rust(exact_inner, &normalized_exact_inner) )
            return {};

        result = util::fmt("(?:%s)", normalized_exact_inner.c_str());
    }
    else {
        std::vector<std::string_view> parts;
        char op = '\0';

        if ( ! split_top_level_wrapped_operands(exact, &parts, &op) )
            return {};

        if ( parts.size() == 1 && op == '\0' )
            result = derive_rust_pattern_from_exact(parts[0]);
        else {
            for ( size_t i = 0; i < parts.size(); ++i ) {
                auto recovered = derive_rust_pattern_from_exact(parts[i]);

                if ( recovered.empty() )
                    return {};

                if ( ! result.empty() && op == '|' )
                    result += '|';

                result += '(';
                result += recovered;
                result += ')';
            }
        }
    }

    if ( result.empty() )
        return {};

    for ( auto it = mode_wrappers.rbegin(); it != mode_wrappers.rend(); ++it )
        result = util::fmt("(?%c:%s)", *it, result.c_str());

    return result;
}

static std::string derive_rust_pattern_text(const char* exact_pat, const char* anywhere_pat) {
    if ( ! exact_pat || ! anywhere_pat )
        return {};

    return derive_rust_pattern_from_exact(exact_pat);
}

Specific_RE_Matcher::Specific_RE_Matcher(match_type arg_mt, bool arg_multiline) : mt(arg_mt), multiline(arg_multiline) {}

Specific_RE_Matcher::~Specific_RE_Matcher() { ClearRustMatchers(); }

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

    std::string normalized_pat;

    if ( ! normalize_zeek_pattern_for_rust(new_pat, &normalized_pat) ) {
        rust_backend_compatible = false;
        rust_pattern_text.clear();
        return;
    }

    if ( ! rust_pattern_text.empty() )
        rust_pattern_text = util::fmt("(?:%s)|(?:%s)", rust_pattern_text.c_str(), normalized_pat.c_str());
    else
        rust_pattern_text = util::fmt("(?:%s)", normalized_pat.c_str());
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
    rust_backend_compatible = pat != nullptr;
    rust_pattern_text = pat ? pat : "";
    ClearRustMatchers();
}

bool Specific_RE_Matcher::Compile(bool lazy) {
    if ( pattern_text.empty() )
        return false;

    ClearRustMatchers();

    if ( ! RustRegexBackendAvailable() ) {
        reporter->Error("Rust regex backend unavailable");
        return false;
    }

    if ( rust_pattern_text.empty() ) {
        reporter->Error("error compiling pattern /%s/", pattern_text.c_str());
        return false;
    }

    rust_matcher = CompileRustRegexMatcher(rust_pattern_text);

    if ( ! rust_matcher ) {
        reporter->Error("error compiling pattern /%s/", pattern_text.c_str());
        return false;
    }

    return true;
}

bool Specific_RE_Matcher::CompileSet(const string_list& set, const int_list& idx, const string_list* rust_set) {
    if ( (size_t)set.length() != idx.size() )
        reporter->InternalError("compileset: lengths of sets differ");

    if ( rust_set && (size_t)rust_set->length() != idx.size() )
        reporter->InternalError("compileset: lengths of Rust sets differ");

    rust_pattern_text.clear();
    ClearRustMatchers();

    std::vector<std::string> normalized_rust_patterns;
    normalized_rust_patterns.reserve(multiline ? set.length() : (rust_set ? rust_set->length() : 0));
    auto append_normalized_pattern = [&](std::string_view pattern, const char* report_pattern) -> bool {
        std::string normalized_pattern;

        if ( ! normalize_zeek_pattern_for_rust(pattern, &normalized_pattern) ) {
            reporter->Error("error compiling pattern /%s/", report_pattern);
            return false;
        }

        normalized_rust_patterns.push_back(std::move(normalized_pattern));
        return true;
    };

    auto append_derived_exact_pattern = [&](const char* exact_pattern) -> bool {
        auto derived_pattern = derive_rust_pattern_from_exact(exact_pattern);

        if ( derived_pattern.empty() ) {
            reporter->Error("error compiling pattern /%s/", exact_pattern);
            return false;
        }

        normalized_rust_patterns.push_back(std::move(derived_pattern));
        return true;
    };

    if ( multiline ) {
        loop_over_list(set, i) {
            if ( ! append_normalized_pattern(set[i], set[i]) )
                return false;
        }
    }
    else if ( rust_set ) {
        loop_over_list((*rust_set), i) {
            if ( ! append_normalized_pattern((*rust_set)[i], set[i]) )
                return false;
        }
    }
    else {
        loop_over_list(set, i) {
            if ( ! append_derived_exact_pattern(set[i]) )
                return false;
        }
    }

    if ( ! RustRegexBackendAvailable() ) {
        reporter->Error("Rust regex backend unavailable");
        return false;
    }

    std::vector<const char*> rust_patterns;
    std::vector<std::intptr_t> rust_ids;
    rust_patterns.reserve(normalized_rust_patterns.size());
    rust_ids.reserve(idx.size());

    for ( const auto& normalized_pattern : normalized_rust_patterns )
        rust_patterns.push_back(normalized_pattern.c_str());

    for ( size_t i = 0; i < idx.size(); ++i )
        rust_ids.push_back(idx[i]);

    if ( multiline ) {
        rust_stream_matcher = CompileRustRegexStreamMatcher(rust_patterns, rust_ids, true, sig_rust_regex_cache_size);

        if ( rust_stream_matcher )
            return true;
    }
    else {
        rust_set_matcher = CompileRustRegexSetMatcher(rust_patterns, rust_ids);

        if ( rust_set_matcher )
            return true;
    }

    for ( size_t i = 0; i < rust_patterns.size(); ++i ) {
        std::vector<const char*> single_pattern = {rust_patterns[i]};
        std::vector<std::intptr_t> single_id = {rust_ids[i]};
        void* matcher = multiline ? CompileRustRegexStreamMatcher(single_pattern, single_id, true,
                                                                 sig_rust_regex_cache_size) :
                                    CompileRustRegexSetMatcher(single_pattern, single_id);

        if ( matcher ) {
            if ( multiline )
                FreeRustRegexStreamMatcher(matcher);
            else
                FreeRustRegexSetMatcher(matcher);

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
}

void Specific_RE_Matcher::Dump(FILE* /* f */) {}

RE_Match_State::RE_Match_State(Specific_RE_Matcher* matcher) {
    current_pos = -1;
    rust_stream_matcher = matcher->RustStreamMatcher();
    rust_stream_state = rust_stream_matcher ? CreateRustRegexStreamState(rust_stream_matcher) : nullptr;
}

RE_Match_State::~RE_Match_State() { FreeRustRegexStreamState(rust_stream_state); }

void RE_Match_State::Clear() {
    current_pos = -1;
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

    TEST_CASE("reconstructed merged matchers derive Rust pattern text from Zeek wrappers") {
        RE_Matcher match1("foo");
        match1.MakeCaseInsensitive();
        REQUIRE(match1.Compile());

        RE_Matcher match2("bar");
        REQUIRE(match2.Compile());

        auto merged = detail::RE_Matcher_disjunction(&match1, &match2);
        RE_Matcher reconstructed(merged->PatternText(), merged->AnywherePatternText());
        REQUIRE(reconstructed.Compile());

        CHECK_FALSE(std::string(reconstructed.RustPatternText()).empty());
        CHECK(reconstructed.MatchExactly("FoO"));
        CHECK(reconstructed.MatchExactly("bar"));

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

        RE_Matcher reconstructed(original.PatternText(), original.AnywherePatternText());
        REQUIRE(reconstructed.Compile());

        CHECK(std::string(reconstructed.RustPatternText()).find("(?-i:") != std::string::npos);
        CHECK(reconstructed.MatchExactly("fOO"));
        CHECK_FALSE(reconstructed.MatchExactly("FoO"));
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
