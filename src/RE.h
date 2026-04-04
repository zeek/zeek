// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h> // for u_char
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "zeek/List.h"
#include "zeek/RegexBackend.h"

namespace zeek {

class String;
class RE_Matcher;

namespace detail {

class Specific_RE_Matcher;

struct MatcherPatternState {
    std::string exact_pattern_text;
    std::string rust_pattern_fallback_text;
    mutable std::string anywhere_pattern_text;
    mutable std::string rust_pattern_text;
    mutable bool anywhere_pattern_text_cached = false;
    mutable bool rust_pattern_text_cached = false;
};

using AcceptIdx = int;
using int_list = std::vector<std::intptr_t>;
using MatchPos = uint64_t;
using AcceptingMatchSet = std::map<AcceptIdx, MatchPos>;
using string_list = name_list;

struct RegexStats {
    unsigned int nfa_states = 0;
    unsigned int dfa_states = 0;
    unsigned int computed = 0;
    unsigned int mem = 0;
    unsigned int hits = 0;
    unsigned int misses = 0;
};

enum match_type : uint8_t { MATCH_ANYWHERE, MATCH_EXACTLY };

// A "specific" RE matcher will match one type of pattern: either
// MATCH_ANYWHERE or MATCH_EXACTLY.

class Specific_RE_Matcher {
public:
    explicit Specific_RE_Matcher(match_type mt, bool multiline = false);
    Specific_RE_Matcher(match_type mt, bool multiline, std::shared_ptr<MatcherPatternState> pattern_state);
    ~Specific_RE_Matcher();

    void AddPat(const char* pat);

    void MakeCaseInsensitive();
    void MakeSingleLine();

    void SetPat(const char* pat);
    void SetRustPat(const char* pat);

    bool Compile(bool lazy = false);

    bool MatchAll(const char* s);
    bool MatchAll(const String* s);
    bool MatchAll(std::string_view sv);

    // Compiles a set of regular expressions simultaneously.
    // 'idx' contains indices associated with the expressions.
    // On matching, the set of indices is returned which correspond
    // to the matching expressions.  (idx must not contain zeros).
    bool CompileSet(const string_list& set, const int_list& idx, const string_list* rust_set = nullptr);

    // For use with CompileSet() to collect indices of all matched
    // expressions into the matches vector. The matches vector is
    // populated with the indices of all matching expressions provided
    // to CompileSet()'s set and idx arguments.
    //
    // Behaves as MatchAll(), consuming the complete input string.
    bool MatchSet(const String* s, std::vector<AcceptIdx>& matches);

    // As MatchSet() above, but taking a std::string_view.
    bool MatchSet(std::string_view sv, std::vector<AcceptIdx>& matches);

    // Returns the position in s just beyond where the first match
    // occurs, or 0 if there is no such position in s.  Note that
    // if the pattern matches empty strings, matching continues
    // in an attempt to match at least one character.
    int Match(const char* s);
    int Match(const String* s);
    int Match(std::string_view sv);
    int Match(const u_char* bv, int n);

    int LongestMatch(const char* s);
    int LongestMatch(const String* s);
    int LongestMatch(std::string_view sv);
    int LongestMatch(const u_char* bv, int n, bool bol = true, bool eol = true);

    const char* PatternText() const;
    const char* RustPatternText() const;
    const RustRegexStreamMatcherHandle& RustStreamMatcher() const { return rust_stream_matcher; }

    unsigned int NumStates() const;
    void GetStats(RegexStats* stats) const;

    void Dump(FILE* f);

protected:
    void AddExactPat(const char* pat);
    void ClearRustMatchers();
    void ClearDerivedTextCaches();

    // Used by the above.  orig_fmt is the format to use when building
    // up a new target string from the given pattern; app_fmt is for when
    // appending to an existing target string.
    void AppendPat(std::string* target, const char* pat, const char* orig_fmt, const char* app_fmt);

    bool MatchAll(const u_char* bv, int n, std::vector<AcceptIdx>* matches = nullptr);

    match_type mt;
    bool multiline;

    std::shared_ptr<MatcherPatternState> pattern_state;

    RustRegexMatcherHandle rust_matcher;
    RustRegexSetMatcherHandle rust_set_matcher;
    RustRegexStreamMatcherHandle rust_stream_matcher;

    friend class ::zeek::RE_Matcher;
};

class RE_Match_State {
public:
    explicit RE_Match_State(Specific_RE_Matcher* matcher);
    ~RE_Match_State();

    const AcceptingMatchSet& AcceptedMatches() const { return accepted_matches; }
    bool UsesRustStreamMatcher() const { return rust_stream_matcher && *rust_stream_matcher; }

    // Returns the number of bytes fed into the matcher so far
    int Length() { return current_pos; }

    // Returns true if this inputs leads to at least one new match.
    // If clear is true, starts matching over.
    bool Match(const u_char* bv, int n, bool bol, bool eol, bool clear);

    void Clear();

protected:
    const RustRegexStreamMatcherHandle* rust_stream_matcher = nullptr;
    RustRegexStreamStateHandle rust_stream_state;

    AcceptingMatchSet accepted_matches;
    int current_pos;
};

extern RE_Matcher* RE_Matcher_conjunction(const RE_Matcher* re1, const RE_Matcher* re2);
extern RE_Matcher* RE_Matcher_disjunction(const RE_Matcher* re1, const RE_Matcher* re2);

} // namespace detail

class RE_Matcher final {
public:
    RE_Matcher();
    explicit RE_Matcher(const char* pat);
    [[nodiscard]] static RE_Matcher* Reconstruct(const char* exact_pat, const char* rust_pat = nullptr);
    ~RE_Matcher();

    void AddPat(const char* pat);
    void SetRustPat(const char* pat);

    // Makes the matcher as specified to date case-insensitive.
    void MakeCaseInsensitive();
    bool IsCaseInsensitive() const { return is_case_insensitive; }

    void MakeSingleLine();
    bool IsSingleLine() const { return is_single_line; }

    bool Compile(bool lazy = false);

    // Returns true if s exactly matches the pattern, false otherwise.
    bool MatchExactly(const char* s) { return re_exact->MatchAll(s); }
    bool MatchExactly(const String* s) { return re_exact->MatchAll(s); }

    // Returns the position in s just beyond where the first match
    // occurs, or 0 if there is no such position in s.  Note that
    // if the pattern matches empty strings, matching continues
    // in an attempt to match at least one character.
    int MatchAnywhere(const char* s) { return re_anywhere->Match(s); }
    int MatchAnywhere(const String* s) { return re_anywhere->Match(s); }

    // Note: it matches the *longest* prefix and returns the
    // length of matched prefix. It returns -1 on mismatch.
    int MatchPrefix(const char* s) { return re_exact->LongestMatch(s); }
    int MatchPrefix(const String* s) { return re_exact->LongestMatch(s); }
    int MatchPrefix(const u_char* s, int n) { return re_exact->LongestMatch(s, n); }

    // MatchPrefix() version allowing control of bol and eol.
    // This can be useful when searching for a pattern with an
    // anchor within a larger string.
    int MatchPrefix(const u_char* s, int n, bool bol, bool eol) { return re_exact->LongestMatch(s, n, bol, eol); }

    bool Match(const u_char* s, int n) { return re_anywhere->Match(s, n); }

    const char* PatternText() const { return re_exact->PatternText(); }
    const char* AnywherePatternText() const { return re_anywhere->PatternText(); }
    const char* RustPatternText() const { return re_exact->RustPatternText(); }

    // Original text used to construct this matcher.  Empty unless
    // the main ("explicit") constructor was used.
    const char* OrigText() const { return orig_text.c_str(); }

protected:
    std::string orig_text;

    detail::Specific_RE_Matcher* re_anywhere;
    detail::Specific_RE_Matcher* re_exact;

    bool is_case_insensitive = false;
    bool is_single_line = false;
};

} // namespace zeek
