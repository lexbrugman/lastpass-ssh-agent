/// Render text that may contain terminal control sequences or invisible
/// Unicode inert: every escaped character becomes a visible `\xNN` (or
/// `\u{NNNN}`) escape, so a crafted vault name cannot move the cursor, clear
/// the screen, forge extra lines, hide characters, or reorder the text
/// around it in a confirmation prompt, an `ssh-add -l` listing, or a log
/// line.
///
/// Two classes are escaped:
///
/// - Control characters — the Unicode `Cc` category, so C0, DEL and C1
///   alike. These drive the terminal.
/// - Bidirectional and zero-width formatting (see `INVISIBLE_RANGES`).
///   These drive the *renderer* rather than the terminal: U+202E and its
///   neighbours reverse the glyph order of everything after them, so a name
///   can display as a different key's name than the one being approved, and
///   the zero-width characters hide text outright. A dialog is exactly the
///   surface where that matters, since the whole point is that the user
///   reads it.
pub fn escape_for_display(text: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if !c.is_control() && !is_invisible(c) {
            out.push(c);
            continue;
        }
        let code = u32::from(c);
        // Two hex digits are unambiguous only up to 0xff; past that, use the
        // braced form so `\x200b` cannot be misread as `\x20` then "0b".
        // (Writing to a String is infallible.)
        if code <= 0xff {
            let _ = write!(out, "\\x{code:02x}");
        } else {
            let _ = write!(out, "\\u{{{code:04x}}}");
        }
    }
    out
}

/// Characters that render as nothing, as inclusive codepoint ranges.
///
/// This is Unicode's own `Default_Ignorable_Code_Point` — the property the
/// standard defines for exactly this question, "renders as no glyph unless
/// explicitly supported" — with two deliberate adjustments:
///
/// - **Variation selectors removed** (U+180B–180D, U+180F, U+FE00–FE0F,
///   U+E0100–E01EF). They are default-ignorable, but emoji are built from
///   them and a mangled emoji in a key name helps nobody.
/// - **Interlinear annotation added** (U+FFF9–FFFB). The standard excludes
///   it from the property, but it exists to wrap text that a renderer hides,
///   which is the thing this function is here to stop.
///
/// Taking the standard's set rather than hand-picking is what keeps this
/// table from growing one codepoint per review. It also gets the awkward
/// cases right for free: the property already excludes the Arabic prepended
/// concatenation marks and the Egyptian hieroglyph controls, which are
/// invisible but belong to real text — so an Arabic or Egyptian name still
/// renders as itself.
///
/// Verified against UCD 17.0 (`DerivedCoreProperties.txt` for the property,
/// `PropList.txt` for `Variation_Selector`): 3917 codepoints, no difference.
/// Every release back to Unicode 9.0 yields the same set, which is why this is
/// a table rather than a dependency — and the space that would absorb a change
/// is already reserved: the tag plane, U+FFF0..FFF8, the U+2065 hole.
const INVISIBLE_RANGES: &[(u32, u32)] = &[
    (0x00ad, 0x00ad),   // SOFT HYPHEN
    (0x034f, 0x034f),   // COMBINING GRAPHEME JOINER
    (0x061c, 0x061c),   // ARABIC LETTER MARK (bidi)
    (0x115f, 0x1160),   // HANGUL CHOSEONG/JUNGSEONG FILLER
    (0x17b4, 0x17b5),   // KHMER VOWEL INHERENT AQ/AA
    (0x180e, 0x180e),   // MONGOLIAN VOWEL SEPARATOR
    (0x200b, 0x200f),   // ZWSP, ZWNJ, ZWJ, LRM, RLM
    (0x202a, 0x202e),   // LRE, RLE, PDF, LRO, RLO — the override attack
    (0x2060, 0x206f),   // WORD JOINER through the isolates, reserved U+2065 too
    (0x3164, 0x3164),   // HANGUL FILLER — the classic invisible-name trick
    (0xfeff, 0xfeff),   // ZWNBSP / BOM
    (0xffa0, 0xffa0),   // HALFWIDTH HANGUL FILLER
    (0xfff0, 0xfffb),   // reserved, then interlinear annotation
    (0x1bca0, 0x1bca3), // shorthand format controls
    (0x1d173, 0x1d17a), // musical beam/slur/phrase controls
    (0xe0000, 0xe00ff), // LANGUAGE TAG, the TAG alphabet, and reserved
    (0xe01f0, 0xe0fff), // the reserved remainder of the tag plane
];

fn is_invisible(c: char) -> bool {
    let code = u32::from(c);
    INVISIBLE_RANGES
        .iter()
        .any(|&(start, end)| (start..=end).contains(&code))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn ordinary_text_is_untouched() {
        assert_eq!(escape_for_display("Personal/SSH Key"), "Personal/SSH Key");
        assert_eq!(escape_for_display("émoji 🔑"), "émoji 🔑");
        // Arabic, Hebrew and CJK render as themselves: only the invisible
        // formatting is escaped, never the script itself.
        assert_eq!(escape_for_display("مفتاح שלי 鍵"), "مفتاح שלי 鍵");
        // a variation selector is a combining mark, not formatting
        assert_eq!(escape_for_display("❤\u{fe0f}"), "❤\u{fe0f}");
    }

    #[test]
    fn control_characters_become_visible_escapes() {
        // C0, DEL, and C1 (U+009B is an alternate CSI) all neutralized
        assert_eq!(escape_for_display("a\r\nb"), "a\\x0d\\x0ab");
        assert_eq!(escape_for_display("\x1b[2J"), "\\x1b[2J");
        assert_eq!(escape_for_display("\x7f"), "\\x7f");
        assert_eq!(escape_for_display("csi\u{9b}2J"), "csi\\x9b2J");
    }

    #[test]
    fn bidi_overrides_cannot_reorder_a_prompt() {
        // The attack this exists for: RLO makes everything after it render
        // right-to-left, so "github\u{202e}yek-live" reads as the reverse.
        assert_eq!(
            escape_for_display("github\u{202e}yek-live"),
            "github\\u{202e}yek-live"
        );
        // every bidi control, not just the override
        for c in ['\u{061c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{2066}'] {
            let escaped = escape_for_display(&c.to_string());
            assert!(escaped.starts_with("\\u{"), "{c:?} -> {escaped}");
        }
    }

    #[test]
    fn zero_width_characters_cannot_hide_text() {
        assert_eq!(escape_for_display("a\u{200b}b"), "a\\u{200b}b");
        assert_eq!(escape_for_display("\u{feff}"), "\\u{feff}");
        assert_eq!(escape_for_display("\u{00ad}"), "\\xad");
        // tag characters are an invisible copy of ASCII
        assert_eq!(escape_for_display("\u{e0041}"), "\\u{e0041}");
        // Hangul fillers: ordinary letters by category, invisible on screen
        assert_eq!(escape_for_display("git\u{3164}hub"), "git\\u{3164}hub");
        assert_eq!(escape_for_display("\u{ffa0}"), "\\u{ffa0}");
        // reserved but default-ignorable: unassigned is not the same as
        // visible, so the gap in the U+2060 block stays closed
        assert_eq!(escape_for_display("\u{2065}"), "\\u{2065}");
        // combining and script-specific ignorables render as no glyph too,
        // so "prod" and "prod\u{034f}" would otherwise look identical
        assert_eq!(escape_for_display("prod\u{034f}"), "prod\\u{034f}");
        assert_eq!(escape_for_display("\u{17b4}"), "\\u{17b4}");
        // the far end of the tag plane, reserved but still ignorable
        assert_eq!(escape_for_display("\u{e0fff}"), "\\u{e0fff}");
    }

    #[test]
    fn characters_just_outside_the_ranges_are_left_alone() {
        // guards the range bounds themselves: a visible neighbour on each
        // side of a range must pass through untouched. U+205F is a real
        // space and U+2070 a printing digit, unlike the U+2060 block
        // between them; U+E1000 is past the tag plane entirely.
        for c in [
            '\u{00ac}',
            '\u{00ae}',
            '\u{0350}',
            '\u{2010}',
            '\u{205f}',
            '\u{2070}',
            '\u{e1000}',
        ] {
            let text = c.to_string();
            assert_eq!(escape_for_display(&text), text, "{c:?} must not escape");
        }
    }
}
