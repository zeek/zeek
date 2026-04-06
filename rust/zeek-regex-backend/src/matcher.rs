use crate::compat;

use regex_automata::{
    meta::Regex,
    nfa::thompson::{self, pikevm},
    util::syntax,
    Anchored, Input, MatchKind, PatternSet,
};

pub struct ZeekRustRegexMatcher {
    regex: Regex,
    exact_regex: Regex,
    prefix_vm: pikevm::PikeVM,
}

pub struct ZeekRustRegexSetMatcher {
    regex: Regex,
    ids: Vec<isize>,
}

struct MatchOutputs<'a> {
    ids: Option<&'a mut [isize]>,
    matched: usize,
}

impl<'a> MatchOutputs<'a> {
    fn new(ids: Option<&'a mut [isize]>) -> Self {
        Self { ids, matched: 0 }
    }

    fn push(&mut self, id: isize) {
        if let Some(ids) = self.ids.as_deref_mut() {
            if self.matched < ids.len() {
                ids[self.matched] = id;
            }
        }

        self.matched += 1;
    }

    fn len(&self) -> usize {
        self.matched
    }
}

fn syntax_config() -> syntax::Config {
    syntax::Config::new().unicode(false).utf8(false)
}

fn bytes_to_pattern(bytes: Vec<u8>) -> Option<String> {
    String::from_utf8(bytes).ok()
}

pub(crate) fn compile_matcher(pattern: &str) -> Option<ZeekRustRegexMatcher> {
    let syntax = syntax_config();
    let regex = Regex::builder().syntax(syntax).build(pattern).ok()?;
    let exact_pattern = format!(r"(?:{pattern})\z");
    let exact_regex = Regex::builder().syntax(syntax).build(&exact_pattern).ok()?;

    let thompson = thompson::Config::new().utf8(false);
    let mut prefix_builder = pikevm::Builder::new();
    prefix_builder.configure(pikevm::Config::new().match_kind(MatchKind::All));
    prefix_builder.syntax(syntax);
    prefix_builder.thompson(thompson);

    let prefix_vm = prefix_builder.build(pattern).ok()?;

    Some(ZeekRustRegexMatcher {
        regex,
        exact_regex,
        prefix_vm,
    })
}

pub(crate) fn compile_matcher_from_zeek_exact(exact: &[u8]) -> Option<ZeekRustRegexMatcher> {
    let pattern = bytes_to_pattern(compat::derive_pattern(exact, true)?)?;
    compile_matcher(&pattern)
}

pub(crate) fn match_all(matcher: &ZeekRustRegexMatcher, haystack: &[u8]) -> i32 {
    let input = Input::new(haystack).anchored(Anchored::Yes);

    match matcher.exact_regex.find(input) {
        Some(found) if found.start() == 0 => 1,
        _ => 0,
    }
}

pub(crate) fn find_end(matcher: &ZeekRustRegexMatcher, haystack: &[u8]) -> usize {
    let input = Input::new(haystack).earliest(true);

    match matcher.regex.find(input) {
        Some(found) if found.end() > found.start() => found.end(),
        Some(_) => 1,
        None => 0,
    }
}

pub(crate) fn longest_prefix(
    matcher: &ZeekRustRegexMatcher,
    haystack: &[u8],
    bol: bool,
    eol: bool,
) -> Option<usize> {
    let mut cache = matcher.prefix_vm.create_cache();
    let find_prefix = |input: Input<'_>, cache: &mut pikevm::Cache| -> Option<usize> {
        match matcher.prefix_vm.find(cache, input.clone()) {
            Some(found) if found.start() == input.start() => Some(found.end() - input.start()),
            _ => None,
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

pub(crate) fn compile_set_matcher(
    patterns: &[&str],
    ids: &[isize],
) -> Option<ZeekRustRegexSetMatcher> {
    if patterns.is_empty() || patterns.len() != ids.len() {
        return None;
    }

    let exact_patterns = patterns
        .iter()
        .map(|pattern| format!(r"(?:{pattern})\z"))
        .collect::<Vec<_>>();

    let regex = Regex::builder()
        .configure(Regex::config().match_kind(MatchKind::All))
        .syntax(syntax_config())
        .build_many(&exact_patterns)
        .ok()?;

    Some(ZeekRustRegexSetMatcher {
        regex,
        ids: ids.to_vec(),
    })
}

pub(crate) fn compile_set_matcher_from_zeek_exact(
    exact_patterns: &[&[u8]],
    ids: &[isize],
) -> Option<ZeekRustRegexSetMatcher> {
    if exact_patterns.is_empty() || exact_patterns.len() != ids.len() {
        return None;
    }

    let patterns = exact_patterns
        .iter()
        .map(|pattern| compat::derive_pattern(pattern, true).and_then(bytes_to_pattern))
        .collect::<Option<Vec<_>>>()?;
    let pattern_refs = patterns.iter().map(String::as_str).collect::<Vec<_>>();
    compile_set_matcher(&pattern_refs, ids)
}

pub(crate) fn set_matcher_pattern_len(matcher: &ZeekRustRegexSetMatcher) -> usize {
    matcher.ids.len()
}

pub(crate) fn write_set_matches(
    matcher: &ZeekRustRegexSetMatcher,
    haystack: &[u8],
    out_ids: Option<&mut [isize]>,
) -> usize {
    let input = Input::new(haystack).anchored(Anchored::Yes);
    let mut patset = PatternSet::new(matcher.ids.len());
    matcher.regex.which_overlapping_matches(&input, &mut patset);

    let mut outputs = MatchOutputs::new(out_ids);

    for pattern_id in patset.iter() {
        outputs.push(matcher.ids[pattern_id.as_usize()]);
    }

    outputs.len()
}
