fn is_octal_digit(byte: u8) -> bool {
    (b'0'..=b'7').contains(&byte)
}

fn is_hex_digit(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn parse_hex_digit(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => 10 + byte - b'a',
        _ => 10 + byte - b'A',
    }
}

fn append_hex_escaped_byte(normalized: &mut Vec<u8>, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    normalized.push(b'\\');
    normalized.push(b'x');
    normalized.push(HEX[(byte >> 4) as usize]);
    normalized.push(HEX[(byte & 0x0f) as usize]);
}

fn consume_zeek_escape(pattern: &[u8], pos: &mut usize) -> Option<u8> {
    if *pos + 1 >= pattern.len() || pattern[*pos + 1] == b'\n' {
        return None;
    }

    let next = pattern[*pos + 1];

    if next == b'x' {
        if *pos + 3 >= pattern.len()
            || !is_hex_digit(pattern[*pos + 2])
            || !is_hex_digit(pattern[*pos + 3])
        {
            return None;
        }

        let byte = (parse_hex_digit(pattern[*pos + 2]) << 4) | parse_hex_digit(pattern[*pos + 3]);
        *pos += 4;
        return Some(byte);
    }

    if is_octal_digit(next) {
        let mut end = *pos + 1;

        while end < pattern.len() && is_octal_digit(pattern[end]) {
            end += 1;
        }

        let digits = (end - (*pos + 1)).min(3);
        let mut value = 0u8;

        for index in 0..digits {
            value = (value << 3) | (pattern[*pos + 1 + index] - b'0');
        }

        *pos = end;
        return Some(value);
    }

    let byte = match next {
        b'b' => b'\x08',
        b'f' => b'\x0c',
        b'n' => b'\n',
        b'r' => b'\r',
        b't' => b'\t',
        b'a' => b'\x07',
        b'v' => b'\x0b',
        _ => next,
    };

    *pos += 2;
    Some(byte)
}

pub(crate) fn normalize_zeek_pattern_for_rust(pattern: &[u8]) -> Option<Vec<u8>> {
    let mut normalized = Vec::with_capacity(pattern.len() + 16);
    let mut in_class = false;
    let mut in_quote = false;
    let mut pos = 0;

    while pos < pattern.len() {
        let byte = pattern[pos];

        if in_quote {
            if byte == b'"' {
                normalized.push(b')');
                in_quote = false;
                pos += 1;
                continue;
            }

            let escaped = if byte == b'\\' {
                consume_zeek_escape(pattern, &mut pos)?
            } else if byte == b'\n' {
                return None;
            } else {
                pos += 1;
                byte
            };

            append_hex_escaped_byte(&mut normalized, escaped);
            continue;
        }

        if byte == b'\\' {
            let escaped = consume_zeek_escape(pattern, &mut pos)?;
            append_hex_escaped_byte(&mut normalized, escaped);
            continue;
        }

        if byte == b'['
            && pos + 2 < pattern.len()
            && pattern[pos + 1] == b'['
            && pattern[pos + 2] == b']'
        {
            append_hex_escaped_byte(&mut normalized, b'[');
            pos += 3;
            continue;
        }

        if byte == b'['
            && pos + 2 < pattern.len()
            && pattern[pos + 1] == b']'
            && pattern[pos + 2] == b']'
        {
            append_hex_escaped_byte(&mut normalized, b']');
            pos += 3;
            continue;
        }

        if byte == b'[' {
            in_class = true;
            normalized.push(byte);
            pos += 1;
            continue;
        }

        if byte == b']' && in_class {
            in_class = false;
            normalized.push(byte);
            pos += 1;
            continue;
        }

        if byte == b'"' && !in_class {
            normalized.extend_from_slice(b"(?-i:");
            in_quote = true;
            pos += 1;
            continue;
        }

        normalized.push(byte);
        pos += 1;
    }

    (!in_quote).then_some(normalized)
}

fn strip_wrapper<'a>(text: &'a [u8], prefix: &[u8], suffix: &[u8]) -> Option<&'a [u8]> {
    text.strip_prefix(prefix)?.strip_suffix(suffix)
}

fn find_matching_paren(text: &[u8], start: usize) -> Option<usize> {
    if start >= text.len() || text[start] != b'(' {
        return None;
    }

    let mut depth = 0usize;
    let mut escaped = false;
    let mut in_class = false;

    for (index, byte) in text.iter().copied().enumerate().skip(start) {
        if escaped {
            escaped = false;
            continue;
        }

        if byte == b'\\' {
            escaped = true;
            continue;
        }

        if in_class {
            if byte == b']' {
                in_class = false;
            }

            continue;
        }

        if byte == b'[' {
            in_class = true;
            continue;
        }

        if byte == b'(' {
            depth += 1;
            continue;
        }

        if byte != b')' {
            continue;
        }

        if depth == 0 {
            return None;
        }

        depth -= 1;

        if depth == 0 {
            return Some(index);
        }
    }

    None
}

fn split_top_level_wrapped_operands(text: &[u8]) -> Option<(Vec<&[u8]>, u8)> {
    let mut parts = Vec::new();
    let mut op = 0u8;
    let mut pos = 0usize;

    while pos < text.len() {
        if text[pos] != b'(' {
            return None;
        }

        let end = find_matching_paren(text, pos)?;
        parts.push(&text[(pos + 1)..end]);
        pos = end + 1;

        if pos == text.len() {
            return (!parts.is_empty()).then_some((parts, op));
        }

        if text[pos] == b'|' {
            if op == 0 {
                op = b'|';
            } else if op != b'|' {
                return None;
            }

            pos += 1;
            continue;
        }

        if text[pos] == b'(' {
            if op == 0 {
                op = b'+';
            } else if op != b'+' {
                return None;
            }

            continue;
        }

        return None;
    }

    (!parts.is_empty()).then_some((parts, op))
}

fn strip_mode_wrappers(text: &mut &[u8]) -> Vec<u8> {
    let mut mode_wrappers = Vec::new();

    loop {
        if text.starts_with(b"(?i:") && text.ends_with(b")") {
            *text = &text[4..(text.len() - 1)];
            mode_wrappers.push(b'i');
            continue;
        }

        if text.starts_with(b"(?s:") && text.ends_with(b")") {
            *text = &text[4..(text.len() - 1)];
            mode_wrappers.push(b's');
            continue;
        }

        return mode_wrappers;
    }
}

fn reapply_mode_wrappers(mut pattern: Vec<u8>, mode_wrappers: &[u8]) -> Vec<u8> {
    for wrapper in mode_wrappers.iter().rev().copied() {
        let mut wrapped = Vec::with_capacity(pattern.len() + 5);
        wrapped.extend_from_slice(b"(?");
        wrapped.push(wrapper);
        wrapped.extend_from_slice(b":");
        wrapped.append(&mut pattern);
        wrapped.push(b')');
        pattern = wrapped;
    }

    pattern
}

pub(crate) fn derive_rust_pattern_from_exact(exact: &[u8]) -> Option<Vec<u8>> {
    let mut exact = exact;
    let mode_wrappers = strip_mode_wrappers(&mut exact);
    let mut result = if let Some(exact_inner) = strip_wrapper(exact, b"^?(", b")$?") {
        let normalized = normalize_zeek_pattern_for_rust(exact_inner)?;
        let mut result = Vec::with_capacity(normalized.len() + 4);
        result.extend_from_slice(b"(?:");
        result.extend_from_slice(&normalized);
        result.push(b')');
        result
    } else {
        let (parts, op) = split_top_level_wrapped_operands(exact)?;

        if parts.len() == 1 && op == 0 {
            derive_rust_pattern_from_exact(parts[0])?
        } else {
            let mut result = Vec::new();

            for recovered in parts
                .iter()
                .map(|part| derive_rust_pattern_from_exact(part))
                .collect::<Option<Vec<_>>>()?
            {
                if !result.is_empty() && op == b'|' {
                    result.push(b'|');
                }

                result.push(b'(');
                result.extend_from_slice(&recovered);
                result.push(b')');
            }

            result
        }
    };

    if result.is_empty() {
        return None;
    }

    result = reapply_mode_wrappers(result, &mode_wrappers);
    Some(result)
}

pub(crate) fn derive_anywhere_pattern_from_exact(exact: &[u8]) -> Option<Vec<u8>> {
    let mut exact = exact;
    let mode_wrappers = strip_mode_wrappers(&mut exact);
    let mut result = if let Some(exact_inner) = strip_wrapper(exact, b"^?(", b")$?") {
        let mut result = Vec::with_capacity(exact_inner.len() + 10);
        result.extend_from_slice(b"^?(.|\\n)*(");
        result.extend_from_slice(exact_inner);
        result.push(b')');
        result
    } else {
        let (parts, op) = split_top_level_wrapped_operands(exact)?;

        if parts.len() == 1 && op == 0 {
            derive_anywhere_pattern_from_exact(parts[0])?
        } else {
            let mut result = Vec::new();

            for recovered in parts
                .iter()
                .map(|part| derive_anywhere_pattern_from_exact(part))
                .collect::<Option<Vec<_>>>()?
            {
                if !result.is_empty() && op == b'|' {
                    result.push(b'|');
                }

                result.push(b'(');
                result.extend_from_slice(&recovered);
                result.push(b')');
            }

            result
        }
    };

    if result.is_empty() {
        return None;
    }

    result = reapply_mode_wrappers(result, &mode_wrappers);
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::{
        derive_anywhere_pattern_from_exact, derive_rust_pattern_from_exact,
        normalize_zeek_pattern_for_rust,
    };

    #[test]
    fn normalize_preserves_quoted_case_sensitive_literals() {
        let normalized = normalize_zeek_pattern_for_rust(br#""fOO""#).expect("normalized");
        assert_eq!(normalized, br"(?-i:\x66\x4f\x4f)");
    }

    #[test]
    fn normalize_rewrites_literal_brackets() {
        let normalized = normalize_zeek_pattern_for_rust(br"[[]").expect("normalized");
        assert_eq!(normalized, br"\x5b");
    }

    #[test]
    fn derive_rust_pattern_from_exact_rebuilds_mode_wrapped_exact_patterns() {
        let derived = derive_rust_pattern_from_exact(br"(?i:^?(foo)$?)").expect("derived");
        assert_eq!(derived, br"(?i:(?:foo))");
    }

    #[test]
    fn derive_rust_pattern_from_exact_rebuilds_wrapped_disjunctions() {
        let derived =
            derive_rust_pattern_from_exact(br"((?i:^?(foo)$?))|(^?(bar)$?)").expect("derived");
        assert_eq!(derived, br"((?i:(?:foo)))|((?:bar))");
    }

    #[test]
    fn derive_anywhere_pattern_from_exact_rebuilds_wrapped_exact_patterns() {
        let derived = derive_anywhere_pattern_from_exact(br"(?s:^?(foo)$?)").expect("derived");
        assert_eq!(derived, br"(?s:^?(.|\n)*(foo))");
    }
}
