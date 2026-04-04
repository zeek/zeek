use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use regex_automata::{
    hybrid::{dfa as hybrid_dfa, LazyStateID},
    nfa::thompson::{self},
    util::{start, syntax},
    Anchored, MatchKind,
};

use crate::{compat, ffi::lock_or_recover};

const UNBOUNDED_STREAM_SHARED_CACHE_CAPACITY: usize = usize::MAX / 2;

pub struct ZeekRustRegexStreamMatcher {
    pub(crate) dfas: Vec<hybrid_dfa::DFA>,
    pub(crate) caches: Vec<Mutex<hybrid_dfa::Cache>>,
    boundary_matches: Vec<Mutex<HashMap<LazyStateID, bool>>>,
    boundary_representatives: Vec<Vec<u8>>,
    ids: Vec<isize>,
}

pub struct ZeekRustRegexStreamState {
    pub(crate) current: Vec<Option<LazyStateID>>,
    current_pos: u64,
    seen: Vec<bool>,
    suppress_next_match: Vec<bool>,
    active: Vec<bool>,
    initialized: bool,
}

struct MatchOutputs<'a> {
    ids: Option<&'a mut [isize]>,
    positions: Option<&'a mut [u64]>,
    matched: usize,
}

impl<'a> MatchOutputs<'a> {
    fn new(ids: Option<&'a mut [isize]>, positions: Option<&'a mut [u64]>) -> Self {
        Self {
            ids,
            positions,
            matched: 0,
        }
    }

    fn push(&mut self, id: isize, position: u64) {
        if let (Some(ids), Some(positions)) =
            (self.ids.as_deref_mut(), self.positions.as_deref_mut())
        {
            if self.matched < ids.len() && self.matched < positions.len() {
                ids[self.matched] = id;
                positions[self.matched] = position;
            }
        }

        self.matched += 1;
    }

    fn len(&self) -> usize {
        self.matched
    }
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
            .cache_capacity(cache_capacity)
            .minimum_cache_clear_count(Some(0)),
    );
    builder.syntax(syntax);
    builder.thompson(thompson);
    builder.build(pattern).ok()
}

fn bytes_to_pattern(bytes: Vec<u8>) -> Option<String> {
    String::from_utf8(bytes).ok()
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
        let boundary_matches = lock_or_recover(&matcher.boundary_matches[pattern_index]);

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

    lock_or_recover(&matcher.boundary_matches[pattern_index]).insert(current, boundary_matchable);
    boundary_matchable
}

fn emit_stream_match(
    matcher: &ZeekRustRegexStreamMatcher,
    state: &mut ZeekRustRegexStreamState,
    pattern_index: usize,
    sid: LazyStateID,
    outputs: &mut MatchOutputs<'_>,
) {
    if !sid.is_match() || state.seen[pattern_index] {
        return;
    }

    if state.suppress_next_match[pattern_index] {
        return;
    }

    state.seen[pattern_index] = true;
    outputs.push(matcher.ids[pattern_index], state.current_pos);
}

fn start_stream_state(
    matcher: &ZeekRustRegexStreamMatcher,
    caches: &mut [std::sync::MutexGuard<'_, hybrid_dfa::Cache>],
    state: &mut ZeekRustRegexStreamState,
    bol: bool,
    outputs: &mut MatchOutputs<'_>,
) {
    let config = start::Config::new()
        .anchored(Anchored::Yes)
        .look_behind(if bol { None } else { Some(0) });

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
        emit_stream_match(matcher, state, pattern_index, sid, outputs);
    }

    state.current_pos = 0;
    state.initialized = true;
}

pub(crate) fn compile_stream_matcher(
    patterns: &[&str],
    ids: &[isize],
    dot_matches_new_line: bool,
    cache_capacity: usize,
) -> Option<ZeekRustRegexStreamMatcher> {
    if patterns.is_empty() || patterns.len() != ids.len() {
        return None;
    }

    let cache_capacity = if cache_capacity == 0 {
        UNBOUNDED_STREAM_SHARED_CACHE_CAPACITY
    } else {
        cache_capacity
    };

    let mut dfas = Vec::with_capacity(patterns.len());

    for pattern in patterns {
        let dfa = build_stream_dfa(pattern, dot_matches_new_line, cache_capacity)?;
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

    Some(ZeekRustRegexStreamMatcher {
        dfas,
        caches,
        boundary_matches,
        boundary_representatives,
        ids: ids.to_vec(),
    })
}

pub(crate) fn compile_stream_matcher_from_zeek_patterns(
    patterns: &[&[u8]],
    ids: &[isize],
    dot_matches_new_line: bool,
    cache_capacity: usize,
) -> Option<ZeekRustRegexStreamMatcher> {
    if patterns.is_empty() || patterns.len() != ids.len() {
        return None;
    }

    let patterns = patterns
        .iter()
        .map(|pattern| compat::normalize_zeek_pattern_for_rust(pattern).and_then(bytes_to_pattern))
        .collect::<Option<Vec<_>>>()?;
    let pattern_refs = patterns.iter().map(String::as_str).collect::<Vec<_>>();
    compile_stream_matcher(&pattern_refs, ids, dot_matches_new_line, cache_capacity)
}

pub(crate) fn stream_matcher_pattern_len(matcher: &ZeekRustRegexStreamMatcher) -> usize {
    matcher.ids.len()
}

pub(crate) fn stream_matcher_cache_bytes(matcher: &ZeekRustRegexStreamMatcher) -> usize {
    matcher
        .caches
        .iter()
        .map(|cache| lock_or_recover(cache).memory_usage())
        .sum()
}

pub(crate) fn stream_matcher_cache_clears(matcher: &ZeekRustRegexStreamMatcher) -> usize {
    matcher
        .caches
        .iter()
        .map(|cache| lock_or_recover(cache).clear_count())
        .sum()
}

pub(crate) fn create_stream_state(
    matcher: &ZeekRustRegexStreamMatcher,
) -> ZeekRustRegexStreamState {
    ZeekRustRegexStreamState {
        current: vec![None; matcher.ids.len()],
        current_pos: 0,
        seen: vec![false; matcher.ids.len()],
        suppress_next_match: vec![false; matcher.ids.len()],
        active: vec![false; matcher.ids.len()],
        initialized: false,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn match_stream_state(
    matcher: &ZeekRustRegexStreamMatcher,
    state: &mut ZeekRustRegexStreamState,
    haystack: &[u8],
    bol: bool,
    eol: bool,
    suppress_initial_empty_visible_match: bool,
    out_ids: Option<&mut [isize]>,
    out_positions: Option<&mut [u64]>,
) -> usize {
    let mut caches = matcher
        .caches
        .iter()
        .map(lock_or_recover)
        .collect::<Vec<_>>();
    let mut outputs = MatchOutputs::new(out_ids, out_positions);

    if !state.initialized {
        start_stream_state(matcher, &mut caches, state, bol, &mut outputs);

        if suppress_initial_empty_visible_match && bol && !eol && haystack.is_empty() {
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
            emit_stream_match(matcher, state, pattern_index, next, &mut outputs);
        }

        state.current_pos += 1;
    }

    if !eol && !haystack.is_empty() {
        for pattern_index in 0..matcher.dfas.len() {
            if !state.active[pattern_index] || state.seen[pattern_index] {
                continue;
            }

            let Some(current) = state.current[pattern_index] else {
                state.active[pattern_index] = false;
                continue;
            };

            if boundary_matchable(matcher, &mut caches[pattern_index], pattern_index, current) {
                let next = match matcher.dfas[pattern_index]
                    .next_eoi_state(&mut caches[pattern_index], current)
                {
                    Ok(next) => next,
                    Err(_) => {
                        state.current[pattern_index] = None;
                        state.active[pattern_index] = false;
                        continue;
                    }
                };

                emit_stream_match(matcher, state, pattern_index, next, &mut outputs);

                if state.seen[pattern_index] {
                    state.active[pattern_index] = false;
                }
            }
        }
    }

    if eol {
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
            emit_stream_match(matcher, state, pattern_index, next, &mut outputs);
        }

        state.current_pos += 1;
    }

    if !haystack.is_empty() || eol {
        for suppress in &mut state.suppress_next_match {
            *suppress = false;
        }
    }

    outputs.len()
}
