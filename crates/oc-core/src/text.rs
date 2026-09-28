//! Text processing utilities.

/// Compute the Levenshtein edit distance between two strings.
///
/// This is used for fuzzy search to find secrets when the user doesn't
/// remember the exact name or spelling.
///
/// # Examples
///
/// ```
/// use oc_core::text::edit_distance;
///
/// assert_eq!(edit_distance("kitten", "sitting"), 3);
/// assert_eq!(edit_distance("", ""), 0);
/// assert_eq!(edit_distance("abc", ""), 3);
/// assert_eq!(edit_distance("", "abc"), 3);
/// ```
pub fn edit_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let a_len = a_chars.len();
    let b_len = b_chars.len();

    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let mut prev_row: Vec<usize> = (0..=b_len).collect();
    let mut curr_row: Vec<usize> = vec![0; b_len + 1];

    for i in 1..=a_len {
        curr_row[0] = i;
        for j in 1..=b_len {
            let cost = usize::from(a_chars[i - 1] != b_chars[j - 1]);
            curr_row[j] = (prev_row[j] + 1).min(curr_row[j - 1] + 1).min(prev_row[j - 1] + cost);
        }
        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    prev_row[b_len]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_distance_empty_strings() {
        assert_eq!(edit_distance("", ""), 0);
    }

    #[test]
    fn edit_distance_one_empty() {
        assert_eq!(edit_distance("abc", ""), 3);
        assert_eq!(edit_distance("", "abc"), 3);
    }

    #[test]
    fn edit_distance_identical() {
        assert_eq!(edit_distance("abc", "abc"), 0);
    }

    #[test]
    fn edit_distance_known_cases() {
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert_eq!(edit_distance("saturday", "sunday"), 3);
        assert_eq!(edit_distance("book", "back"), 2);
    }

    #[test]
    fn edit_distance_unicode() {
        assert_eq!(edit_distance("café", "cafe"), 1);
        assert_eq!(edit_distance("日本語", "日本"), 1);
    }
}
