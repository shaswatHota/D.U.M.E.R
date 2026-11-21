//! Bounded Levenshtein distance for fuzzy command matching.
#![forbid(unsafe_code)]

/// Computes the Levenshtein distance between `a` and `b`, bounded by `max_dist`.
///
/// Returns `Some(distance)` if distance <= `max_dist`, or `None` if distance exceeds `max_dist`.
/// Designed for low allocation overhead on short command phrases.
pub fn levenshtein_bounded(a: &str, b: &str, max_dist: usize) -> Option<usize> {
    if a == b {
        return Some(0);
    }

    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();

    let a_len = a_chars.len();
    let b_len = b_chars.len();

    // If length difference exceeds max_dist, distance must exceed max_dist.
    let diff = a_len.abs_diff(b_len);
    if diff > max_dist {
        return None;
    }

    // Ensure b is the shorter array to minimize memory
    let (short, long, s_len, l_len) = if a_len < b_len {
        (&a_chars, &b_chars, a_len, b_len)
    } else {
        (&b_chars, &a_chars, b_len, a_len)
    };

    let mut prev_row: Vec<usize> = (0..=s_len).collect();
    let mut curr_row: Vec<usize> = vec![0; s_len + 1];

    for i in 1..=l_len {
        curr_row[0] = i;
        let mut min_in_row = curr_row[0];

        for j in 1..=s_len {
            let cost = if long[i - 1] == short[j - 1] { 0 } else { 1 };
            let deletion = prev_row[j] + 1;
            let insertion = curr_row[j - 1] + 1;
            let substitution = prev_row[j - 1] + cost;

            let min_val = deletion.min(insertion).min(substitution);
            curr_row[j] = min_val;
            if min_val < min_in_row {
                min_in_row = min_val;
            }
        }

        // Early exit: if the minimum edit distance in this row already exceeds max_dist,
        // it cannot possibly converge within max_dist.
        if min_in_row > max_dist {
            return None;
        }

        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    let final_dist = prev_row[s_len];
    if final_dist <= max_dist {
        Some(final_dist)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_levenshtein_bounded() {
        assert_eq!(levenshtein_bounded("chrome", "chrome", 2), Some(0));
        assert_eq!(levenshtein_bounded("chrme", "chrome", 2), Some(1));
        assert_eq!(levenshtein_bounded("chromx", "chrome", 2), Some(1));
        assert_eq!(levenshtein_bounded("opn chrme", "open chrome", 2), Some(2));
        assert_eq!(levenshtein_bounded("zzzzz", "chrome", 2), None);
        assert_eq!(levenshtein_bounded("status", "system status", 2), None);
    }
}
