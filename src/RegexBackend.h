// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

struct ZeekRustRegexMatcher;
struct ZeekRustRegexSetMatcher;
struct ZeekRustRegexStreamMatcher;
struct ZeekRustRegexStreamState;

uint32_t zeek_rust_regex_backend_abi_version(void);
uint32_t zeek_rust_regex_backend_smoke_test(void);
ZeekRustRegexMatcher* zeek_rust_regex_matcher_compile(const char* pattern);
ZeekRustRegexMatcher* zeek_rust_regex_matcher_compile_from_zeek_exact(const char* exact);
void zeek_rust_regex_matcher_free(ZeekRustRegexMatcher* matcher);
int zeek_rust_regex_matcher_match_all(const ZeekRustRegexMatcher* matcher, const uint8_t* data, size_t len);
int zeek_rust_regex_matcher_find_end(const ZeekRustRegexMatcher* matcher, const uint8_t* data, size_t len);
int zeek_rust_regex_matcher_longest_prefix(const ZeekRustRegexMatcher* matcher, const uint8_t* data, size_t len,
                                           int bol, int eol);
char* zeek_rust_regex_compat_normalize_pattern(const char* pattern);
char* zeek_rust_regex_compat_derive_rust_pattern_from_exact(const char* exact);
char* zeek_rust_regex_compat_derive_anywhere_pattern_from_exact(const char* exact);
void zeek_rust_regex_string_free(char* text);
ZeekRustRegexSetMatcher* zeek_rust_regex_set_matcher_compile(const char* const* patterns, const intptr_t* ids,
                                                             size_t len);
ZeekRustRegexSetMatcher* zeek_rust_regex_set_matcher_compile_from_zeek_exact(const char* const* patterns,
                                                                             const intptr_t* ids, size_t len);
void zeek_rust_regex_set_matcher_free(ZeekRustRegexSetMatcher* matcher);
size_t zeek_rust_regex_set_matcher_pattern_len(const ZeekRustRegexSetMatcher* matcher);
size_t zeek_rust_regex_set_matcher_matches(const ZeekRustRegexSetMatcher* matcher, const uint8_t* data, size_t len,
                                           intptr_t* out_ids, size_t out_capacity);
ZeekRustRegexStreamMatcher* zeek_rust_regex_stream_matcher_compile(const char* const* patterns, const intptr_t* ids,
                                                                   size_t len, int dot_matches_new_line,
                                                                   size_t cache_capacity);
ZeekRustRegexStreamMatcher* zeek_rust_regex_stream_matcher_compile_from_zeek(const char* const* patterns,
                                                                             const intptr_t* ids, size_t len,
                                                                             int dot_matches_new_line,
                                                                             size_t cache_capacity);
void zeek_rust_regex_stream_matcher_free(ZeekRustRegexStreamMatcher* matcher);
size_t zeek_rust_regex_stream_matcher_pattern_len(const ZeekRustRegexStreamMatcher* matcher);
ZeekRustRegexStreamState* zeek_rust_regex_stream_state_create(const ZeekRustRegexStreamMatcher* matcher);
void zeek_rust_regex_stream_state_free(ZeekRustRegexStreamState* state);
size_t zeek_rust_regex_stream_state_match(const ZeekRustRegexStreamMatcher* matcher, ZeekRustRegexStreamState* state,
                                          const uint8_t* data, size_t len, int bol, int eol,
                                          int suppress_initial_empty_visible_match, intptr_t* out_ids,
                                          uint64_t* out_positions, size_t out_capacity);

#ifdef __cplusplus
}

namespace zeek::detail {

inline constexpr uint32_t ZEEK_RUST_REGEX_BACKEND_ABI_VERSION = 4;
inline constexpr uint32_t ZEEK_RUST_REGEX_BACKEND_SMOKE_TEST_TOKEN = 0x5A45'454B;

uint32_t RustRegexBackendAbiVersion();
uint32_t RustRegexBackendSmokeTest();
bool RustRegexBackendAvailable();
bool NormalizeZeekPatternForRust(const char* pattern, std::string* normalized);
std::string DeriveRustPatternFromExact(const char* exact);
std::string DeriveAnywherePatternFromExact(const char* exact);
void* CompileRustRegexMatcher(const std::string& pattern);
void* CompileRustRegexMatcherFromExact(const std::string& exact_pattern);
void FreeRustRegexMatcher(void* matcher);
bool RustRegexMatcherMatchAll(const void* matcher, const uint8_t* data, size_t len);
int RustRegexMatcherFindEnd(const void* matcher, const uint8_t* data, size_t len);
int RustRegexMatcherLongestPrefix(const void* matcher, const uint8_t* data, size_t len, bool bol, bool eol);
void* CompileRustRegexSetMatcher(const std::vector<const char*>& patterns, const std::vector<std::intptr_t>& ids);
void* CompileRustRegexSetMatcherFromExact(const std::vector<const char*>& exact_patterns,
                                          const std::vector<std::intptr_t>& ids);
void FreeRustRegexSetMatcher(void* matcher);
bool RustRegexSetMatcherMatchAny(const void* matcher, const uint8_t* data, size_t len);
void RustRegexSetMatcherAppendMatches(const void* matcher, const uint8_t* data, size_t len, std::vector<int>& matches);
void* CompileRustRegexStreamMatcher(const std::vector<const char*>& patterns, const std::vector<std::intptr_t>& ids,
                                    bool dot_matches_new_line, size_t cache_capacity);
void* CompileRustRegexStreamMatcherFromZeek(const std::vector<const char*>& patterns,
                                            const std::vector<std::intptr_t>& ids, bool dot_matches_new_line,
                                            size_t cache_capacity);
void FreeRustRegexStreamMatcher(void* matcher);
void* CreateRustRegexStreamState(const void* matcher);
void FreeRustRegexStreamState(void* state);
void RustRegexStreamStateAppendMatches(const void* matcher, void* state, const uint8_t* data, size_t len, bool bol,
                                       bool eol, bool suppress_initial_empty_visible_match,
                                       std::vector<std::pair<int, uint64_t>>& matches);

} // namespace zeek::detail

#endif
