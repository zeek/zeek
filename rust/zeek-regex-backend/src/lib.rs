use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::slice;
use std::sync::{Mutex, MutexGuard};

use regex_automata::{
    hybrid::{dfa as hybrid_dfa, LazyStateID},
    meta::Regex,
    nfa::thompson::{self, pikevm},
    util::{start, syntax},
    Anchored, Input, MatchKind, PatternSet,
};

pub const ZEEK_RUST_REGEX_BACKEND_ABI_VERSION: u32 = 3;
pub const ZEEK_RUST_REGEX_BACKEND_SMOKE_TEST_TOKEN: u32 = 0x5A45_454B;
const UNBOUNDED_STREAM_SHARED_CACHE_CAPACITY: usize = usize::MAX / 2;

pub struct ZeekRustRegexMatcher {
    regex: Regex,
    prefix_vm: pikevm::PikeVM,
}

pub struct ZeekRustRegexSetMatcher {
    regex: Regex,
    ids: Vec<isize>,
}

pub struct ZeekRustRegexStreamMatcher {
    dfas: Vec<hybrid_dfa::DFA>,
    caches: Vec<Mutex<hybrid_dfa::Cache>>,
    boundary_matches: Vec<Mutex<HashMap<LazyStateID, bool>>>,
    boundary_representatives: Vec<Vec<u8>>,
    ids: Vec<isize>,
}

pub struct ZeekRustRegexStreamState {
    current: Vec<Option<LazyStateID>>,
    current_pos: u64,
    seen: Vec<bool>,
    suppress_next_match: Vec<bool>,
    active: Vec<bool>,
    initialized: bool,
}

fn build_stream_dfa(
    pattern: &str,
    dot_matches_new_line: bool,
    cache_capacity: usize,
) -> Option<hybrid_dfa::DFA> {
    let syntax = syntax::Config::new()
        .unicode(false)
        .utf8(false)
        .dot_matches_new_line(dot_matches_new_line);
    let thompson = thompson::Config::new().utf8(false);
    let mut builder = hybrid_dfa::Builder::new();
    builder.configure(
        hybrid_dfa::Config::new()
            .match_kind(MatchKind::LeftmostFirst)
            // We keep lazy state IDs in per-stream match state, so cache clearing
            // would invalidate them. Keep the cache append-only and let actual
            // process memory, not cache clearing, be the practical limit by
            // default.
            .cache_capacity(cache_capacity)
            .minimum_cache_clear_count(Some(0)),
    );
    builder.syntax(syntax);
    builder.thompson(thompson);
    builder.build(pattern).ok()
}

fn can_reach_match_after_boundary(
    dfa: &hybrid_dfa::DFA,
    representatives: &[u8],
    cache: &mut hybrid_dfa::Cache,
    current: LazyStateID,
) -> bool {
    if dfa.get_nfa().has_empty() {
        return false;
    }

    let Ok(eoi) = dfa.next_eoi_state(cache, current) else {
        return false;
    };

    if !eoi.is_match() {
        return false;
    }

    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();

    for &byte in representatives {
        let Ok(next) = dfa.next_state(cache, current, byte) else {
            continue;
        };

        if next.is_dead() || next.is_quit() {
            continue;
        }

        if next.is_match() {
            return true;
        }

        if visited.insert(next) {
            queue.push_back(next);
        }
    }

    while let Some(state) = queue.pop_front() {
        for &byte in representatives {
            let Ok(next) = dfa.next_state(cache, state, byte) else {
                continue;
            };

            if next.is_dead() || next.is_quit() {
                continue;
            }

            if next.is_match() {
                return true;
            }

            if visited.insert(next) {
                queue.push_back(next);
            }
        }
    }

    false
}

fn boundary_matchable(
    matcher: &ZeekRustRegexStreamMatcher,
    cache: &mut hybrid_dfa::Cache,
    pattern_index: usize,
    current: LazyStateID,
) -> bool {
    {
        let boundary_matches = matcher.boundary_matches[pattern_index]
            .lock()
            .expect("shared boundary memo poisoned");
        if let Some(boundary_matchable) = boundary_matches.get(&current) {
            return *boundary_matchable;
        }
    }

    let boundary_matchable = can_reach_match_after_boundary(
        &matcher.dfas[pattern_index],
        &matcher.boundary_representatives[pattern_index],
        cache,
        current,
    );

    matcher.boundary_matches[pattern_index]
        .lock()
        .expect("shared boundary memo poisoned")
        .insert(current, boundary_matchable);
    boundary_matchable
}

unsafe fn haystack_from_raw<'a>(data: *const u8, len: usize) -> Option<&'a [u8]> {
    if data.is_null() {
        if len == 0 {
            Some(&[][..])
        } else {
            None
        }
    } else {
        Some(slice::from_raw_parts(data, len))
    }
}

fn longest_prefix_with_pikevm(
    matcher: &ZeekRustRegexMatcher,
    haystack: &[u8],
    bol: bool,
    eol: bool,
) -> i32 {
    let mut cache = matcher.prefix_vm.create_cache();
    let find_prefix = |input: Input<'_>, cache: &mut pikevm::Cache| -> i32 {
        match matcher.prefix_vm.find(cache, input.clone()) {
            Some(found) if found.start() == input.start() => (found.end() - input.start()) as i32,
            _ => -1,
        }
    };

    if bol && eol {
        return find_prefix(Input::new(haystack).anchored(Anchored::Yes), &mut cache);
    }

    let prefix_len = usize::from(!bol);
    let suffix_len = usize::from(!eol);
    let mut contextual = Vec::with_capacity(prefix_len + haystack.len() + suffix_len);

    if !bol {
        contextual.push(0);
    }

    contextual.extend_from_slice(haystack);

    if !eol {
        contextual.push(0);
    }

    find_prefix(
        Input::new(&contextual)
            .span(prefix_len..(prefix_len + haystack.len()))
            .anchored(Anchored::Yes),
        &mut cache,
    )
}

#[no_mangle]
pub extern "C" fn zeek_rust_regex_backend_abi_version() -> u32 {
    ZEEK_RUST_REGEX_BACKEND_ABI_VERSION
}

#[no_mangle]
pub extern "C" fn zeek_rust_regex_backend_smoke_test() -> u32 {
    ZEEK_RUST_REGEX_BACKEND_SMOKE_TEST_TOKEN
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_matcher_compile(
    pattern: *const c_char,
) -> *mut ZeekRustRegexMatcher {
    if pattern.is_null() {
        return std::ptr::null_mut();
    }

    let pattern = match CStr::from_ptr(pattern).to_str() {
        Ok(pattern) => pattern,
        Err(_) => return std::ptr::null_mut(),
    };

    let syntax = syntax::Config::new().unicode(false).utf8(false);
    let regex = match Regex::builder().syntax(syntax).build(pattern) {
        Ok(regex) => regex,
        Err(_) => return std::ptr::null_mut(),
    };

    let thompson = thompson::Config::new().utf8(false);
    let mut prefix_builder = pikevm::Builder::new();
    prefix_builder.configure(pikevm::Config::new().match_kind(MatchKind::All));
    prefix_builder.syntax(syntax);
    prefix_builder.thompson(thompson);

    let prefix_vm = match prefix_builder.build(pattern) {
        Ok(vm) => vm,
        Err(_) => return std::ptr::null_mut(),
    };

    Box::into_raw(Box::new(ZeekRustRegexMatcher { regex, prefix_vm }))
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_matcher_free(matcher: *mut ZeekRustRegexMatcher) {
    if !matcher.is_null() {
        drop(Box::from_raw(matcher));
    }
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_matcher_match_all(
    matcher: *const ZeekRustRegexMatcher,
    data: *const u8,
    len: usize,
) -> i32 {
    let Some(matcher) = matcher.as_ref() else {
        return 0;
    };

    let Some(haystack) = haystack_from_raw(data, len) else {
        return 0;
    };

    let input = Input::new(haystack).anchored(Anchored::Yes);
    match matcher.regex.find(input) {
        Some(found) if found.start() == 0 && found.end() == haystack.len() => 1,
        _ => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_matcher_find_end(
    matcher: *const ZeekRustRegexMatcher,
    data: *const u8,
    len: usize,
) -> i32 {
    let Some(matcher) = matcher.as_ref() else {
        return 0;
    };

    let Some(haystack) = haystack_from_raw(data, len) else {
        return 0;
    };

    let input = Input::new(haystack).earliest(true);
    match matcher.regex.find(input) {
        Some(found) if found.end() > found.start() => found.end() as i32,
        Some(_) => 1,
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_matcher_longest_prefix(
    matcher: *const ZeekRustRegexMatcher,
    data: *const u8,
    len: usize,
    bol: i32,
    eol: i32,
) -> i32 {
    let Some(matcher) = matcher.as_ref() else {
        return -1;
    };

    let Some(haystack) = haystack_from_raw(data, len) else {
        return -1;
    };

    longest_prefix_with_pikevm(matcher, haystack, bol != 0, eol != 0)
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_set_matcher_compile(
    patterns: *const *const c_char,
    ids: *const isize,
    len: usize,
) -> *mut ZeekRustRegexSetMatcher {
    if patterns.is_null() || ids.is_null() || len == 0 {
        return std::ptr::null_mut();
    }

    let pattern_ptrs = slice::from_raw_parts(patterns, len);
    let pattern_ids = slice::from_raw_parts(ids, len);
    let mut exact_patterns = Vec::with_capacity(len);

    for pattern in pattern_ptrs {
        if pattern.is_null() {
            return std::ptr::null_mut();
        }

        let pattern = match CStr::from_ptr(*pattern).to_str() {
            Ok(pattern) => pattern,
            Err(_) => return std::ptr::null_mut(),
        };

        exact_patterns.push(format!(r"(?:{})\z", pattern));
    }

    let syntax = syntax::Config::new().unicode(false).utf8(false);
    let regex = match Regex::builder()
        .configure(Regex::config().match_kind(MatchKind::All))
        .syntax(syntax)
        .build_many(&exact_patterns)
    {
        Ok(regex) => regex,
        Err(_) => return std::ptr::null_mut(),
    };

    Box::into_raw(Box::new(ZeekRustRegexSetMatcher {
        regex,
        ids: pattern_ids.to_vec(),
    }))
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_set_matcher_free(matcher: *mut ZeekRustRegexSetMatcher) {
    if !matcher.is_null() {
        drop(Box::from_raw(matcher));
    }
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_set_matcher_pattern_len(
    matcher: *const ZeekRustRegexSetMatcher,
) -> usize {
    matcher.as_ref().map_or(0, |matcher| matcher.ids.len())
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_set_matcher_matches(
    matcher: *const ZeekRustRegexSetMatcher,
    data: *const u8,
    len: usize,
    out_ids: *mut isize,
    out_capacity: usize,
) -> usize {
    let Some(matcher) = matcher.as_ref() else {
        return 0;
    };

    let Some(haystack) = haystack_from_raw(data, len) else {
        return 0;
    };

    let input = Input::new(haystack).anchored(Anchored::Yes);
    let mut patset = PatternSet::new(matcher.ids.len());
    matcher.regex.which_overlapping_matches(&input, &mut patset);

    let mut matched = 0;

    for pattern_id in patset.iter() {
        let index = pattern_id.as_usize();

        if matched < out_capacity && !out_ids.is_null() {
            *out_ids.add(matched) = matcher.ids[index];
        }

        matched += 1;
    }

    matched
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_stream_matcher_compile(
    patterns: *const *const c_char,
    ids: *const isize,
    len: usize,
    dot_matches_new_line: i32,
    cache_capacity: usize,
) -> *mut ZeekRustRegexStreamMatcher {
    if patterns.is_null() || ids.is_null() || len == 0 {
        return std::ptr::null_mut();
    }

    let pattern_ptrs = slice::from_raw_parts(patterns, len);
    let pattern_ids = slice::from_raw_parts(ids, len);
    let mut dfas = Vec::with_capacity(len);

    let cache_capacity = if cache_capacity == 0 {
        UNBOUNDED_STREAM_SHARED_CACHE_CAPACITY
    } else {
        cache_capacity
    };

    for pattern in pattern_ptrs {
        if pattern.is_null() {
            return std::ptr::null_mut();
        }

        let pattern = match CStr::from_ptr(*pattern).to_str() {
            Ok(pattern) => pattern,
            Err(_) => return std::ptr::null_mut(),
        };

        let Some(dfa) = build_stream_dfa(pattern, dot_matches_new_line != 0, cache_capacity) else {
            return std::ptr::null_mut();
        };

        dfas.push(dfa);
    }

    let caches = dfas
        .iter()
        .map(|dfa| Mutex::new(dfa.create_cache()))
        .collect::<Vec<_>>();
    let boundary_matches = (0..dfas.len())
        .map(|_| Mutex::new(HashMap::new()))
        .collect::<Vec<_>>();
    let boundary_representatives = dfas
        .iter()
        .map(|dfa| {
            dfa.byte_classes()
                .representatives(..=u8::MAX)
                .filter_map(|unit| unit.as_u8())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    Box::into_raw(Box::new(ZeekRustRegexStreamMatcher {
        dfas,
        caches,
        boundary_matches,
        boundary_representatives,
        ids: pattern_ids.to_vec(),
    }))
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_stream_matcher_free(
    matcher: *mut ZeekRustRegexStreamMatcher,
) {
    if !matcher.is_null() {
        drop(Box::from_raw(matcher));
    }
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_stream_matcher_pattern_len(
    matcher: *const ZeekRustRegexStreamMatcher,
) -> usize {
    matcher.as_ref().map_or(0, |matcher| matcher.ids.len())
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_stream_state_create(
    matcher: *const ZeekRustRegexStreamMatcher,
) -> *mut ZeekRustRegexStreamState {
    let Some(matcher) = matcher.as_ref() else {
        return std::ptr::null_mut();
    };

    Box::into_raw(Box::new(ZeekRustRegexStreamState {
        current: vec![None; matcher.ids.len()],
        current_pos: 0,
        seen: vec![false; matcher.ids.len()],
        suppress_next_match: vec![false; matcher.ids.len()],
        active: vec![false; matcher.ids.len()],
        initialized: false,
    }))
}

#[no_mangle]
pub unsafe extern "C" fn zeek_rust_regex_stream_state_free(state: *mut ZeekRustRegexStreamState) {
    if !state.is_null() {
        drop(Box::from_raw(state));
    }
}

unsafe fn emit_stream_match(
    matcher: &ZeekRustRegexStreamMatcher,
    state: &mut ZeekRustRegexStreamState,
    pattern_index: usize,
    sid: LazyStateID,
    out_ids: *mut isize,
    out_positions: *mut u64,
    out_capacity: usize,
    matched: &mut usize,
) {
    if !sid.is_match() || state.seen[pattern_index] {
        return;
    }

    if state.suppress_next_match[pattern_index] {
        return;
    }

    state.seen[pattern_index] = true;

    if *matched < out_capacity && !out_ids.is_null() && !out_positions.is_null() {
        *out_ids.add(*matched) = matcher.ids[pattern_index];
        *out_positions.add(*matched) = state.current_pos;
    }

    *matched += 1;
}

unsafe fn start_stream_state(
    matcher: &ZeekRustRegexStreamMatcher,
    caches: &mut [MutexGuard<'_, hybrid_dfa::Cache>],
    state: &mut ZeekRustRegexStreamState,
    bol: i32,
    out_ids: *mut isize,
    out_positions: *mut u64,
    out_capacity: usize,
    matched: &mut usize,
) {
    let config = start::Config::new()
        .anchored(Anchored::Yes)
        .look_behind(if bol != 0 { None } else { Some(0) });

    for (pattern_index, dfa) in matcher.dfas.iter().enumerate() {
        let sid = match dfa.start_state(&mut caches[pattern_index], &config) {
            Ok(sid) => sid,
            Err(_) => {
                state.current[pattern_index] = None;
                state.active[pattern_index] = false;
                continue;
            }
        };

        state.current[pattern_index] = Some(sid);
        state.active[pattern_index] = true;
        emit_stream_match(
            matcher,
            state,
            pattern_index,
            sid,
            out_ids,
            out_positions,
            out_capacity,
            matched,
        );
    }

    state.current_pos = 0;
    state.initialized = true;
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
    let Some(matcher) = matcher.as_ref() else {
        return 0;
    };
    let Some(state) = state.as_mut() else {
        return 0;
    };
    let Some(haystack) = haystack_from_raw(data, len) else {
        return 0;
    };
    let mut caches = matcher
        .caches
        .iter()
        .map(|cache| cache.lock().expect("shared stream cache poisoned"))
        .collect::<Vec<_>>();

    let mut matched = 0;

    if !state.initialized {
        start_stream_state(
            matcher,
            &mut caches,
            state,
            bol,
            out_ids,
            out_positions,
            out_capacity,
            &mut matched,
        );

        if suppress_initial_empty_visible_match != 0 && bol != 0 && eol == 0 && haystack.is_empty() {
            for (pattern_index, dfa) in matcher.dfas.iter().enumerate() {
                if dfa.get_nfa().has_empty() {
                    state.suppress_next_match[pattern_index] = true;
                }
            }
        }
    }

    for &byte in haystack {
        for (pattern_index, dfa) in matcher.dfas.iter().enumerate() {
            if !state.active[pattern_index] {
                continue;
            }

            let Some(current) = state.current[pattern_index] else {
                state.active[pattern_index] = false;
                continue;
            };

            let next = match dfa.next_state(&mut caches[pattern_index], current, byte) {
                Ok(next) => next,
                Err(_) => {
                    state.current[pattern_index] = None;
                    state.active[pattern_index] = false;
                    continue;
                }
            };

            if next.is_dead() || next.is_quit() {
                state.current[pattern_index] = None;
                state.active[pattern_index] = false;
                continue;
            }

            state.current[pattern_index] = Some(next);
            emit_stream_match(
                matcher,
                state,
                pattern_index,
                next,
                out_ids,
                out_positions,
                out_capacity,
                &mut matched,
            );
        }

        state.current_pos += 1;
    }

    if eol == 0 && len > 0 {
        for pattern_index in 0..matcher.dfas.len() {
            if !state.active[pattern_index] || state.seen[pattern_index] {
                continue;
            }

            let Some(current) = state.current[pattern_index] else {
                state.active[pattern_index] = false;
                continue;
            };

            if boundary_matchable(matcher, &mut caches[pattern_index], pattern_index, current) {
                let next = match matcher.dfas[pattern_index].next_eoi_state(&mut caches[pattern_index], current) {
                    Ok(next) => next,
                    Err(_) => {
                        state.current[pattern_index] = None;
                        state.active[pattern_index] = false;
                        continue;
                    }
                };

                emit_stream_match(
                    matcher,
                    state,
                    pattern_index,
                    next,
                    out_ids,
                    out_positions,
                    out_capacity,
                    &mut matched,
                );

                if state.seen[pattern_index] {
                    state.active[pattern_index] = false;
                }
            }
        }
    }

    if eol != 0 {
        for (pattern_index, dfa) in matcher.dfas.iter().enumerate() {
            if !state.active[pattern_index] {
                continue;
            }

            let Some(current) = state.current[pattern_index] else {
                state.active[pattern_index] = false;
                continue;
            };

            let next = match dfa.next_eoi_state(&mut caches[pattern_index], current) {
                Ok(next) => next,
                Err(_) => {
                    state.current[pattern_index] = None;
                    state.active[pattern_index] = false;
                    continue;
                }
            };

            if next.is_dead() || next.is_quit() {
                state.current[pattern_index] = None;
                state.active[pattern_index] = false;
                continue;
            }

            state.current[pattern_index] = Some(next);
            emit_stream_match(
                matcher,
                state,
                pattern_index,
                next,
                out_ids,
                out_positions,
                out_capacity,
                &mut matched,
            );
        }

        state.current_pos += 1;
    }

    if !haystack.is_empty() || eol != 0 {
        for suppress in &mut state.suppress_next_match {
            *suppress = false;
        }
    }

    matched
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn compile_matcher(pattern: &str) -> *mut ZeekRustRegexMatcher {
        let pattern = CString::new(pattern).expect("pattern cstring");
        unsafe { zeek_rust_regex_matcher_compile(pattern.as_ptr()) }
    }

    fn compile_stream_matcher(patterns: &[&str]) -> *mut ZeekRustRegexStreamMatcher {
        let patterns = patterns
            .iter()
            .map(|pattern| CString::new(*pattern).expect("pattern cstring"))
            .collect::<Vec<_>>();
        let pattern_ptrs = patterns.iter().map(|pattern| pattern.as_ptr()).collect::<Vec<_>>();
        let ids = (1..=patterns.len()).map(|id| id as isize).collect::<Vec<_>>();

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
        let matcher = compile_stream_matcher(&["XXXX", "^XXXX", ".*XXXX", "YYYY", "^YYYY", ".*YYYY"]);
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
            let mut cache = matcher_ref.caches[0].lock().expect("shared stream cache poisoned");
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
            let mut cache = matcher_ref.caches[0].lock().expect("shared stream cache poisoned");
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
            let mut cache = matcher_ref.caches[0].lock().expect("shared stream cache poisoned");
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
