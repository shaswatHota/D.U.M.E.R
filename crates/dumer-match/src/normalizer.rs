//! Input phrase normalization for deterministic command matching.
#![forbid(unsafe_code)]

/// Normalizes an input phrase for deterministic matching.
///
/// Steps:
/// 1. Strips leading and trailing whitespace.
/// 2. Converts ASCII characters to lowercase.
/// 3. Collapses internal consecutive whitespace characters to a single space.
/// 4. Strips surrounding matching quotes (`"`, `'`, `` ` ``).
/// 5. Strips trailing punctuation (`.`, `!`, `?`, `,`, `;`, `:`, `...`).
pub fn normalize(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // Strip surrounding quotes
    let unquoted = if (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        || (trimmed.starts_with('`') && trimmed.ends_with('`'))
    {
        if trimmed.len() >= 2 {
            &trimmed[1..trimmed.len() - 1]
        } else {
            trimmed
        }
    } else {
        trimmed
    };

    // Strip trailing punctuation
    let mut end = unquoted.len();
    let bytes = unquoted.as_bytes();
    while end > 0 {
        let b = bytes[end - 1];
        if b == b'.' || b == b'!' || b == b'?' || b == b',' || b == b';' || b == b':' {
            end -= 1;
        } else {
            break;
        }
    }
    let stripped = &unquoted[..end].trim();

    // Lowercase and collapse consecutive whitespace
    let mut result = String::with_capacity(stripped.len());
    let mut prev_is_space = false;

    for ch in stripped.chars() {
        if ch.is_whitespace() {
            if !prev_is_space && !result.is_empty() {
                result.push(' ');
                prev_is_space = true;
            }
        } else {
            result.push(ch.to_ascii_lowercase());
            prev_is_space = false;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_variations() {
        assert_eq!(normalize("  Open Chrome!  "), "open chrome");
        assert_eq!(normalize("OPEN CHROME..."), "open chrome");
        assert_eq!(normalize("open    chrome???"), "open chrome");
        assert_eq!(normalize("\"open chrome\""), "open chrome");
        assert_eq!(normalize("open chrome."), "open chrome");
        assert_eq!(normalize("   "), "");
    }
}
