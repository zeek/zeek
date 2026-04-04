#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]

mod compat;
mod ffi;
mod matcher;
mod stream;

use std::os::raw::c_char;
use std::ptr::null_mut;

pub const ZEEK_RUST_REGEX_BACKEND_ABI_VERSION: u32 = 5;
pub const ZEEK_RUST_REGEX_BACKEND_SMOKE_TEST_TOKEN: u32 = 0x5A45_454B;
pub use matcher::{ZeekRustRegexMatcher, ZeekRustRegexSetMatcher};
pub use stream::{ZeekRustRegexStreamMatcher, ZeekRustRegexStreamState};

#[no_mangle]
pub extern "C" fn zeek_rust_regex_backend_abi_version() -> u32 {
    ZEEK_RUST_REGEX_BACKEND_ABI_VERSION
}

#[no_mangle]
pub extern "C" fn zeek_rust_regex_backend_smoke_test() -> u32 {
    ZEEK_RUST_REGEX_BACKEND_SMOKE_TEST_TOKEN
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_compat_normalize_pattern(
    pattern: *const c_char,
) -> *mut c_char {
    let Some(pattern) = (unsafe { ffi::cstr_bytes_arg(pattern) }) else {
        return null_mut();
    };

    compat::normalize_zeek_pattern_for_rust(pattern).map_or(null_mut(), ffi::into_c_string_ptr)
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_compat_derive_rust_pattern_from_exact(
    exact: *const c_char,
) -> *mut c_char {
    let Some(exact) = (unsafe { ffi::cstr_bytes_arg(exact) }) else {
        return null_mut();
    };

    compat::derive_rust_pattern_from_exact(exact).map_or(null_mut(), ffi::into_c_string_ptr)
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_compat_derive_anywhere_pattern_from_exact(
    exact: *const c_char,
) -> *mut c_char {
    let Some(exact) = (unsafe { ffi::cstr_bytes_arg(exact) }) else {
        return null_mut();
    };

    compat::derive_anywhere_pattern_from_exact(exact).map_or(null_mut(), ffi::into_c_string_ptr)
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_string_free(text: *mut c_char) {
    unsafe { ffi::free_c_string(text) };
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_matcher_compile(
    pattern: *const c_char,
) -> *mut ZeekRustRegexMatcher {
    let Some(pattern) = (unsafe { ffi::cstr_arg(pattern) }) else {
        return null_mut();
    };

    matcher::compile_matcher(pattern).map_or(null_mut(), |matcher| Box::into_raw(Box::new(matcher)))
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_matcher_compile_from_zeek_exact(
    exact: *const c_char,
) -> *mut ZeekRustRegexMatcher {
    let Some(exact) = (unsafe { ffi::cstr_bytes_arg(exact) }) else {
        return null_mut();
    };

    matcher::compile_matcher_from_zeek_exact(exact)
        .map_or(null_mut(), |matcher| Box::into_raw(Box::new(matcher)))
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_matcher_free(matcher: *mut ZeekRustRegexMatcher) {
    unsafe { ffi::free_boxed(matcher) };
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_matcher_match_all(
    matcher: *const ZeekRustRegexMatcher,
    data: *const u8,
    len: usize,
) -> i32 {
    let Some(matcher) = (unsafe { ffi::handle_ref(matcher) }) else {
        return 0;
    };

    let Some(haystack) = (unsafe { ffi::slice_arg(data, len) }) else {
        return 0;
    };

    matcher::match_all(matcher, haystack)
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_matcher_find_end(
    matcher: *const ZeekRustRegexMatcher,
    data: *const u8,
    len: usize,
) -> i32 {
    let Some(matcher) = (unsafe { ffi::handle_ref(matcher) }) else {
        return 0;
    };

    let Some(haystack) = (unsafe { ffi::slice_arg(data, len) }) else {
        return 0;
    };

    matcher::find_end(matcher, haystack)
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_matcher_longest_prefix(
    matcher: *const ZeekRustRegexMatcher,
    data: *const u8,
    len: usize,
    bol: i32,
    eol: i32,
) -> i32 {
    let Some(matcher) = (unsafe { ffi::handle_ref(matcher) }) else {
        return -1;
    };

    let Some(haystack) = (unsafe { ffi::slice_arg(data, len) }) else {
        return -1;
    };

    matcher::longest_prefix(matcher, haystack, bol != 0, eol != 0)
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_set_matcher_compile(
    patterns: *const *const c_char,
    ids: *const isize,
    len: usize,
) -> *mut ZeekRustRegexSetMatcher {
    if len == 0 {
        return null_mut();
    }

    let Some(pattern_ptrs) = (unsafe { ffi::slice_arg(patterns, len) }) else {
        return null_mut();
    };
    let Some(pattern_ids) = (unsafe { ffi::slice_arg(ids, len) }) else {
        return null_mut();
    };

    let mut rust_patterns = Vec::with_capacity(len);

    for pattern in pattern_ptrs {
        let Some(pattern) = (unsafe { ffi::cstr_arg(*pattern) }) else {
            return null_mut();
        };

        rust_patterns.push(pattern);
    }

    matcher::compile_set_matcher(&rust_patterns, pattern_ids)
        .map_or(null_mut(), |matcher| Box::into_raw(Box::new(matcher)))
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_set_matcher_compile_from_zeek_exact(
    patterns: *const *const c_char,
    ids: *const isize,
    len: usize,
) -> *mut ZeekRustRegexSetMatcher {
    if len == 0 {
        return null_mut();
    }

    let Some(pattern_ptrs) = (unsafe { ffi::slice_arg(patterns, len) }) else {
        return null_mut();
    };
    let Some(pattern_ids) = (unsafe { ffi::slice_arg(ids, len) }) else {
        return null_mut();
    };

    let mut zeek_patterns = Vec::with_capacity(len);

    for pattern in pattern_ptrs {
        let Some(pattern) = (unsafe { ffi::cstr_bytes_arg(*pattern) }) else {
            return null_mut();
        };

        zeek_patterns.push(pattern);
    }

    matcher::compile_set_matcher_from_zeek_exact(&zeek_patterns, pattern_ids)
        .map_or(null_mut(), |matcher| Box::into_raw(Box::new(matcher)))
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_set_matcher_free(matcher: *mut ZeekRustRegexSetMatcher) {
    unsafe { ffi::free_boxed(matcher) };
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_set_matcher_pattern_len(
    matcher: *const ZeekRustRegexSetMatcher,
) -> usize {
    let Some(matcher) = (unsafe { ffi::handle_ref(matcher) }) else {
        return 0;
    };

    matcher::set_matcher_pattern_len(matcher)
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_set_matcher_matches(
    matcher: *const ZeekRustRegexSetMatcher,
    data: *const u8,
    len: usize,
    out_ids: *mut isize,
    out_capacity: usize,
) -> usize {
    let Some(matcher) = (unsafe { ffi::handle_ref(matcher) }) else {
        return 0;
    };

    let Some(haystack) = (unsafe { ffi::slice_arg(data, len) }) else {
        return 0;
    };

    let out_ids = if out_capacity == 0 || out_ids.is_null() {
        None
    } else {
        match unsafe { ffi::mut_slice_arg(out_ids, out_capacity) } {
            Some(out_ids) => Some(out_ids),
            None => return 0,
        }
    };

    matcher::write_set_matches(matcher, haystack, out_ids)
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_stream_matcher_compile(
    patterns: *const *const c_char,
    ids: *const isize,
    len: usize,
    dot_matches_new_line: i32,
    cache_capacity: usize,
) -> *mut ZeekRustRegexStreamMatcher {
    if len == 0 {
        return null_mut();
    }

    let Some(pattern_ptrs) = (unsafe { ffi::slice_arg(patterns, len) }) else {
        return null_mut();
    };
    let Some(pattern_ids) = (unsafe { ffi::slice_arg(ids, len) }) else {
        return null_mut();
    };

    let mut rust_patterns = Vec::with_capacity(len);

    for pattern in pattern_ptrs {
        let Some(pattern) = (unsafe { ffi::cstr_arg(*pattern) }) else {
            return null_mut();
        };

        rust_patterns.push(pattern);
    }

    stream::compile_stream_matcher(
        &rust_patterns,
        pattern_ids,
        dot_matches_new_line != 0,
        cache_capacity,
    )
    .map_or(null_mut(), |matcher| Box::into_raw(Box::new(matcher)))
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_stream_matcher_compile_from_zeek(
    patterns: *const *const c_char,
    ids: *const isize,
    len: usize,
    dot_matches_new_line: i32,
    cache_capacity: usize,
) -> *mut ZeekRustRegexStreamMatcher {
    if len == 0 {
        return null_mut();
    }

    let Some(pattern_ptrs) = (unsafe { ffi::slice_arg(patterns, len) }) else {
        return null_mut();
    };
    let Some(pattern_ids) = (unsafe { ffi::slice_arg(ids, len) }) else {
        return null_mut();
    };

    let mut zeek_patterns = Vec::with_capacity(len);

    for pattern in pattern_ptrs {
        let Some(pattern) = (unsafe { ffi::cstr_bytes_arg(*pattern) }) else {
            return null_mut();
        };

        zeek_patterns.push(pattern);
    }

    stream::compile_stream_matcher_from_zeek_patterns(
        &zeek_patterns,
        pattern_ids,
        dot_matches_new_line != 0,
        cache_capacity,
    )
    .map_or(null_mut(), |matcher| Box::into_raw(Box::new(matcher)))
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_stream_matcher_free(
    matcher: *mut ZeekRustRegexStreamMatcher,
) {
    unsafe { ffi::free_boxed(matcher) };
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_stream_matcher_pattern_len(
    matcher: *const ZeekRustRegexStreamMatcher,
) -> usize {
    let Some(matcher) = (unsafe { ffi::handle_ref(matcher) }) else {
        return 0;
    };

    stream::stream_matcher_pattern_len(matcher)
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_stream_matcher_cache_bytes(
    matcher: *const ZeekRustRegexStreamMatcher,
) -> usize {
    let Some(matcher) = (unsafe { ffi::handle_ref(matcher) }) else {
        return 0;
    };

    stream::stream_matcher_cache_bytes(matcher)
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_stream_matcher_cache_clears(
    matcher: *const ZeekRustRegexStreamMatcher,
) -> usize {
    let Some(matcher) = (unsafe { ffi::handle_ref(matcher) }) else {
        return 0;
    };

    stream::stream_matcher_cache_clears(matcher)
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_stream_state_create(
    matcher: *const ZeekRustRegexStreamMatcher,
) -> *mut ZeekRustRegexStreamState {
    let Some(matcher) = (unsafe { ffi::handle_ref(matcher) }) else {
        return null_mut();
    };

    Box::into_raw(Box::new(stream::create_stream_state(matcher)))
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_stream_state_free(state: *mut ZeekRustRegexStreamState) {
    unsafe { ffi::free_boxed(state) };
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_stream_state_match(
    matcher: *const ZeekRustRegexStreamMatcher,
    state: *mut ZeekRustRegexStreamState,
    data: *const u8,
    len: usize,
    bol: i32,
    eol: i32,
    suppress_initial_empty_visible_match: i32,
    out_ids: *mut isize,
    out_positions: *mut u64,
    out_capacity: usize,
) -> usize {
    let Some(matcher) = (unsafe { ffi::handle_ref(matcher) }) else {
        return 0;
    };
    let Some(state) = (unsafe { ffi::handle_mut(state) }) else {
        return 0;
    };
    let Some(haystack) = (unsafe { ffi::slice_arg(data, len) }) else {
        return 0;
    };

    let (out_ids, out_positions) =
        if out_capacity == 0 || out_ids.is_null() || out_positions.is_null() {
            (None, None)
        } else {
            let Some(out_ids) = (unsafe { ffi::mut_slice_arg(out_ids, out_capacity) }) else {
                return 0;
            };
            let Some(out_positions) = (unsafe { ffi::mut_slice_arg(out_positions, out_capacity) })
            else {
                return 0;
            };

            (Some(out_ids), Some(out_positions))
        };

    stream::match_stream_state(
        matcher,
        state,
        haystack,
        bol != 0,
        eol != 0,
        suppress_initial_empty_visible_match != 0,
        out_ids,
        out_positions,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn compile_matcher(pattern: &str) -> *mut ZeekRustRegexMatcher {
        let pattern = CString::new(pattern).expect("pattern cstring");
        unsafe { zeek_rust_regex_matcher_compile(pattern.as_ptr()) }
    }

    fn compile_matcher_from_zeek_exact(pattern: &str) -> *mut ZeekRustRegexMatcher {
        let pattern = CString::new(pattern).expect("pattern cstring");
        unsafe { zeek_rust_regex_matcher_compile_from_zeek_exact(pattern.as_ptr()) }
    }

    fn compile_stream_matcher(patterns: &[&str]) -> *mut ZeekRustRegexStreamMatcher {
        let patterns = patterns
            .iter()
            .map(|pattern| CString::new(*pattern).expect("pattern cstring"))
            .collect::<Vec<_>>();
        let pattern_ptrs = patterns
            .iter()
            .map(|pattern| pattern.as_ptr())
            .collect::<Vec<_>>();
        let ids = (1..=patterns.len())
            .map(|id| id as isize)
            .collect::<Vec<_>>();

        unsafe {
            zeek_rust_regex_stream_matcher_compile(
                pattern_ptrs.as_ptr(),
                ids.as_ptr(),
                ids.len(),
                1,
                0,
            )
        }
    }

    fn compile_stream_matcher_from_zeek(patterns: &[&str]) -> *mut ZeekRustRegexStreamMatcher {
        let patterns = patterns
            .iter()
            .map(|pattern| CString::new(*pattern).expect("pattern cstring"))
            .collect::<Vec<_>>();
        let pattern_ptrs = patterns
            .iter()
            .map(|pattern| pattern.as_ptr())
            .collect::<Vec<_>>();
        let ids = (1..=patterns.len())
            .map(|id| id as isize)
            .collect::<Vec<_>>();

        unsafe {
            zeek_rust_regex_stream_matcher_compile_from_zeek(
                pattern_ptrs.as_ptr(),
                ids.as_ptr(),
                ids.len(),
                1,
                0,
            )
        }
    }

    #[test]
    fn stream_matcher_compiles_simple_pattern() {
        let matcher = compile_stream_matcher(&["foo"]);
        assert!(!matcher.is_null());

        unsafe {
            zeek_rust_regex_stream_matcher_free(matcher);
        }
    }

    #[test]
    fn stream_matcher_compiles_signature_like_pattern() {
        let matcher =
            compile_stream_matcher(&[".*portability.*", ".*portability.*", ".*portability.*"]);
        assert!(!matcher.is_null());

        unsafe {
            zeek_rust_regex_stream_matcher_free(matcher);
        }
    }

    #[test]
    fn matcher_compiles_from_zeek_exact_wrapper() {
        let matcher = compile_matcher_from_zeek_exact("(?i:^?(foo)$?)");
        assert!(!matcher.is_null());
        assert_eq!(
            unsafe { zeek_rust_regex_matcher_match_all(matcher, b"FoO".as_ptr(), 3) },
            1
        );

        unsafe {
            zeek_rust_regex_matcher_free(matcher);
        }
    }

    #[test]
    fn stream_matcher_compiles_from_zeek_patterns() {
        let matcher = compile_stream_matcher_from_zeek(&["\"fOO\""]);
        assert!(!matcher.is_null());

        unsafe {
            zeek_rust_regex_stream_matcher_free(matcher);
        }
    }

    #[test]
    fn stream_matcher_reuses_shared_cache_across_states() {
        let matcher = compile_stream_matcher(&["^ABCDEFGHIJ$"]);
        assert!(!matcher.is_null());

        let matcher_ref = unsafe { &*matcher };
        let before = matcher_ref.caches[0]
            .lock()
            .expect("shared stream cache poisoned")
            .memory_usage();

        let state1 = unsafe { zeek_rust_regex_stream_state_create(matcher) };
        assert!(!state1.is_null());

        let mut ids = [0isize; 2];
        let mut positions = [0u64; 2];
        let matched = unsafe {
            zeek_rust_regex_stream_state_match(
                matcher,
                state1,
                b"ABCDE".as_ptr(),
                5,
                1,
                0,
                0,
                ids.as_mut_ptr(),
                positions.as_mut_ptr(),
                ids.len(),
            )
        };
        assert_eq!(matched, 0);

        let after_first = matcher_ref.caches[0]
            .lock()
            .expect("shared stream cache poisoned")
            .memory_usage();
        assert!(after_first > before);

        let state2 = unsafe { zeek_rust_regex_stream_state_create(matcher) };
        assert!(!state2.is_null());

        let matched = unsafe {
            zeek_rust_regex_stream_state_match(
                matcher,
                state2,
                b"ABCDE".as_ptr(),
                5,
                1,
                0,
                0,
                ids.as_mut_ptr(),
                positions.as_mut_ptr(),
                ids.len(),
            )
        };
        assert_eq!(matched, 0);

        let after_second = matcher_ref.caches[0]
            .lock()
            .expect("shared stream cache poisoned")
            .memory_usage();
        assert_eq!(after_second, after_first);

        unsafe {
            zeek_rust_regex_stream_state_free(state2);
            zeek_rust_regex_stream_state_free(state1);
            zeek_rust_regex_stream_matcher_free(matcher);
        }
    }

    #[test]
    fn stream_matcher_matches_packetwise_payload() {
        let matcher =
            compile_stream_matcher(&["XXXX", "^XXXX", ".*XXXX", "YYYY", "^YYYY", ".*YYYY"]);
        assert!(!matcher.is_null());

        let state = unsafe { zeek_rust_regex_stream_state_create(matcher) };
        assert!(!state.is_null());

        let mut ids = [0isize; 8];
        let mut positions = [0u64; 8];

        let matched = unsafe {
            zeek_rust_regex_stream_state_match(
                matcher,
                state,
                [].as_ptr(),
                0,
                1,
                0,
                1,
                ids.as_mut_ptr(),
                positions.as_mut_ptr(),
                ids.len(),
            )
        };
        assert_eq!(matched, 0);

        let matched = unsafe {
            zeek_rust_regex_stream_state_match(
                matcher,
                state,
                b"XXXX".as_ptr(),
                4,
                1,
                1,
                1,
                ids.as_mut_ptr(),
                positions.as_mut_ptr(),
                ids.len(),
            )
        };

        let got = ids[..matched].to_vec();
        assert_eq!(got, vec![1, 2, 3]);
        assert_eq!(positions[..matched].to_vec(), vec![4, 4, 4]);

        unsafe {
            zeek_rust_regex_stream_state_free(state);
            zeek_rust_regex_stream_matcher_free(matcher);
        }
    }

    #[test]
    fn matcher_longest_prefix_prefers_longer_accept() {
        let matcher = compile_matcher("a|ab");
        assert!(!matcher.is_null());

        let matched =
            unsafe { zeek_rust_regex_matcher_longest_prefix(matcher, b"abx".as_ptr(), 3, 1, 0) };
        assert_eq!(matched, 2);

        unsafe {
            zeek_rust_regex_matcher_free(matcher);
        }
    }

    #[test]
    fn matcher_longest_prefix_honors_bol_and_eol() {
        let anchored = compile_matcher("^ab$");
        assert!(!anchored.is_null());

        let no_eol =
            unsafe { zeek_rust_regex_matcher_longest_prefix(anchored, b"ab".as_ptr(), 2, 1, 0) };
        assert_eq!(no_eol, -1);

        let with_eol =
            unsafe { zeek_rust_regex_matcher_longest_prefix(anchored, b"ab".as_ptr(), 2, 1, 1) };
        assert_eq!(with_eol, 2);

        let no_bol =
            unsafe { zeek_rust_regex_matcher_longest_prefix(anchored, b"ab".as_ptr(), 2, 0, 1) };
        assert_eq!(no_bol, -1);

        unsafe {
            zeek_rust_regex_matcher_free(anchored);
        }
    }

    #[test]
    fn stream_matcher_matches_empty_capable_patterns_on_nonempty_input() {
        let matcher = compile_stream_matcher(&[".*"]);
        assert!(!matcher.is_null());

        let state = unsafe { zeek_rust_regex_stream_state_create(matcher) };
        assert!(!state.is_null());

        let mut ids = [0isize; 4];
        let mut positions = [0u64; 4];

        let matched = unsafe {
            zeek_rust_regex_stream_state_match(
                matcher,
                state,
                b"packet".as_ptr(),
                6,
                1,
                0,
                0,
                ids.as_mut_ptr(),
                positions.as_mut_ptr(),
                ids.len(),
            )
        };
        assert_eq!(matched, 1);
        assert_eq!(ids[0], 1);
        assert_eq!(positions[0], 0);

        unsafe {
            zeek_rust_regex_stream_state_free(state);
            zeek_rust_regex_stream_matcher_free(matcher);
        }
    }

    #[test]
    fn stream_matcher_consumes_first_visible_empty_match_after_initial_bol() {
        let matcher = compile_stream_matcher(&[".*"]);
        assert!(!matcher.is_null());

        let state = unsafe { zeek_rust_regex_stream_state_create(matcher) };
        assert!(!state.is_null());

        let mut ids = [0isize; 4];
        let mut positions = [0u64; 4];

        let matched = unsafe {
            zeek_rust_regex_stream_state_match(
                matcher,
                state,
                [].as_ptr(),
                0,
                1,
                0,
                1,
                ids.as_mut_ptr(),
                positions.as_mut_ptr(),
                ids.len(),
            )
        };
        assert_eq!(matched, 0);

        let matched = unsafe {
            zeek_rust_regex_stream_state_match(
                matcher,
                state,
                b"packet".as_ptr(),
                6,
                1,
                0,
                1,
                ids.as_mut_ptr(),
                positions.as_mut_ptr(),
                ids.len(),
            )
        };
        assert_eq!(matched, 0);

        let matched = unsafe {
            zeek_rust_regex_stream_state_match(
                matcher,
                state,
                b"next".as_ptr(),
                4,
                1,
                0,
                1,
                ids.as_mut_ptr(),
                positions.as_mut_ptr(),
                ids.len(),
            )
        };
        assert_eq!(matched, 1);

        unsafe {
            zeek_rust_regex_stream_state_free(state);
            zeek_rust_regex_stream_matcher_free(matcher);
        }
    }

    #[test]
    fn stream_matcher_keeps_first_visible_empty_match_outside_bare_mode() {
        let matcher = compile_stream_matcher(&[".*"]);
        assert!(!matcher.is_null());

        let state = unsafe { zeek_rust_regex_stream_state_create(matcher) };
        assert!(!state.is_null());

        let mut ids = [0isize; 4];
        let mut positions = [0u64; 4];

        let matched = unsafe {
            zeek_rust_regex_stream_state_match(
                matcher,
                state,
                [].as_ptr(),
                0,
                1,
                0,
                0,
                ids.as_mut_ptr(),
                positions.as_mut_ptr(),
                ids.len(),
            )
        };
        assert_eq!(matched, 0);

        let matched = unsafe {
            zeek_rust_regex_stream_state_match(
                matcher,
                state,
                b"packet".as_ptr(),
                6,
                0,
                0,
                0,
                ids.as_mut_ptr(),
                positions.as_mut_ptr(),
                ids.len(),
            )
        };
        assert_eq!(matched, 1);
        assert_eq!(ids[0], 1);
        assert_eq!(positions[0], 0);

        unsafe {
            zeek_rust_regex_stream_state_free(state);
            zeek_rust_regex_stream_matcher_free(matcher);
        }
    }

    #[test]
    fn stream_matcher_matches_split_anchored_prefix() {
        let matcher = compile_stream_matcher(&["^AB"]);
        assert!(!matcher.is_null());

        let state = unsafe { zeek_rust_regex_stream_state_create(matcher) };
        assert!(!state.is_null());

        let matcher_ref = unsafe { &*matcher };
        let dfa = &matcher_ref.dfas[0];

        let mut ids = [0isize; 4];
        let mut positions = [0u64; 4];

        let matched = unsafe {
            zeek_rust_regex_stream_state_match(
                matcher,
                state,
                b"A".as_ptr(),
                1,
                1,
                0,
                0,
                ids.as_mut_ptr(),
                positions.as_mut_ptr(),
                ids.len(),
            )
        };
        assert_eq!(matched, 0);
        let current = unsafe { (&(*state).current)[0].expect("state after A") };
        assert!(!current.is_match());

        let matched = unsafe {
            zeek_rust_regex_stream_state_match(
                matcher,
                state,
                b"B".as_ptr(),
                1,
                0,
                0,
                0,
                ids.as_mut_ptr(),
                positions.as_mut_ptr(),
                ids.len(),
            )
        };
        let current = unsafe { (&(*state).current)[0].expect("state after B") };
        let eoi = {
            let mut cache = matcher_ref.caches[0]
                .lock()
                .expect("shared stream cache poisoned");
            dfa.next_eoi_state(&mut cache, current)
                .expect("eoi transition after split prefix")
        };
        assert!(
            current.is_match() || eoi.is_match(),
            "state after B should be a match or become one at EOI"
        );
        assert_eq!(matched, 1);
        assert_eq!(ids[0], 1);
        assert_eq!(positions[0], 2);

        unsafe {
            zeek_rust_regex_stream_state_free(state);
            zeek_rust_regex_stream_matcher_free(matcher);
        }
    }

    #[test]
    fn stream_matcher_matches_split_anchored_exact_on_eoi() {
        let matcher = compile_stream_matcher(&["^AB$"]);
        assert!(!matcher.is_null());

        let state = unsafe { zeek_rust_regex_stream_state_create(matcher) };
        assert!(!state.is_null());

        let matcher_ref = unsafe { &*matcher };
        let dfa = &matcher_ref.dfas[0];

        let mut ids = [0isize; 4];
        let mut positions = [0u64; 4];

        let matched = unsafe {
            zeek_rust_regex_stream_state_match(
                matcher,
                state,
                b"A".as_ptr(),
                1,
                1,
                0,
                0,
                ids.as_mut_ptr(),
                positions.as_mut_ptr(),
                ids.len(),
            )
        };
        assert_eq!(matched, 0);

        let current = unsafe { (&(*state).current)[0].expect("state after A exact") };
        assert!(!current.is_match());
        let eoi = {
            let mut cache = matcher_ref.caches[0]
                .lock()
                .expect("shared stream cache poisoned");
            dfa.next_eoi_state(&mut cache, current)
                .expect("eoi transition after partial exact")
        };
        assert!(!eoi.is_match());

        let matched = unsafe {
            zeek_rust_regex_stream_state_match(
                matcher,
                state,
                b"B".as_ptr(),
                1,
                0,
                0,
                0,
                ids.as_mut_ptr(),
                positions.as_mut_ptr(),
                ids.len(),
            )
        };
        assert_eq!(matched, 0);

        let current = unsafe { (&(*state).current)[0].expect("state after B exact") };
        assert!(!current.is_match());
        let eoi = {
            let mut cache = matcher_ref.caches[0]
                .lock()
                .expect("shared stream cache poisoned");
            dfa.next_eoi_state(&mut cache, current)
                .expect("eoi transition after exact suffix")
        };
        assert!(eoi.is_match());

        let matched = unsafe {
            zeek_rust_regex_stream_state_match(
                matcher,
                state,
                [].as_ptr(),
                0,
                0,
                1,
                0,
                ids.as_mut_ptr(),
                positions.as_mut_ptr(),
                ids.len(),
            )
        };
        assert_eq!(matched, 1);
        assert_eq!(ids[0], 1);
        assert_eq!(positions[0], 2);

        unsafe {
            zeek_rust_regex_stream_state_free(state);
            zeek_rust_regex_stream_matcher_free(matcher);
        }
    }
}
