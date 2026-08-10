/// Render text that may contain terminal control sequences inert: every
/// control character becomes a visible `\xNN` escape, so a crafted vault
/// name cannot move the cursor, clear the screen, or forge extra lines in a
/// confirmation prompt, an `ssh-add -l` listing, or a log line.
/// `is_control` is the Unicode `Cc` category — C0, DEL, and C1 alike.
pub fn escape_control(text: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            // writing to a String is infallible
            let _ = write!(out, "\\x{:02x}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn ordinary_text_is_untouched() {
        assert_eq!(escape_control("Personal/SSH Key"), "Personal/SSH Key");
        assert_eq!(escape_control("émoji 🔑"), "émoji 🔑");
    }

    #[test]
    fn control_characters_become_visible_escapes() {
        // C0, DEL, and C1 (U+009B is an alternate CSI) all neutralized
        assert_eq!(escape_control("a\r\nb"), "a\\x0d\\x0ab");
        assert_eq!(escape_control("\x1b[2J"), "\\x1b[2J");
        assert_eq!(escape_control("\x7f"), "\\x7f");
        assert_eq!(escape_control("csi\u{9b}2J"), "csi\\x9b2J");
    }
}
