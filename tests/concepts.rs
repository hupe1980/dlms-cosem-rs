//! The architecture notes, checked the way code is.
//!
//! `concepts/` is not tracked — it is internal design documentation, git-ignored on
//! purpose — so **this test skips when the directory is absent**, which is what CI sees.
//! On a working copy that has it, the documents are held to three properties that a
//! reader relies on and that nothing else enforces:
//!
//! 1. Every relative link between them resolves. A document that points at a file that
//!    is not there is worse than one that says nothing, because it reads as a map.
//! 2. `D` and `R` numbers are **contiguous from one**. They are stable identifiers cited
//!    from the other documents and from code comments, so a gap means an entry was
//!    deleted and the citations to it now point at nothing.
//! 3. Every `D<n>` or `R<n>` cited anywhere in the set names an entry that exists.
//!
//! None of this checks that a document is *true*. That is what the rest of the suite is
//! for, and the layer tables carry a state marker precisely because prose cannot be
//! tested. What this catches is the decay a directory of cross-referenced documents
//! suffers on its own: a renumbering, a rename, a deleted section still cited.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn concepts_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("concepts");
    dir.is_dir().then_some(dir)
}

/// Every `*.md` in `concepts/`, as (file name, contents).
fn documents(dir: &Path) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = fs::read_dir(dir)
        .expect("concepts/ is readable")
        .filter_map(|e| {
            let path = e.ok()?.path();
            if path.extension()? != "md" {
                return None;
            }
            let name = path.file_name()?.to_str()?.to_string();
            Some((name, fs::read_to_string(&path).ok()?))
        })
        .collect();
    out.sort();
    out
}

/// The numbers of every entry defined in `file`, from headings of the form `**D7 — …**`.
fn defined(text: &str, letter: char) -> BTreeSet<u32> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("**") else { continue };
        let mut chars = rest.chars();
        if chars.next() != Some(letter) {
            continue;
        }
        let digits: String = chars.take_while(char::is_ascii_digit).collect();
        if let Ok(n) = digits.parse() {
            out.insert(n);
        }
    }
    out
}

/// Every `D<n>` / `R<n>` mentioned anywhere in `text`.
fn cited(text: &str, letter: char) -> BTreeSet<u32> {
    let mut out = BTreeSet::new();
    let bytes: Vec<char> = text.chars().collect();
    for (i, c) in bytes.iter().enumerate() {
        if *c != letter {
            continue;
        }
        // Only a citation when it stands on its own: `D8` yes, `ID8` and `D8x` no.
        if i > 0 && (bytes[i - 1].is_alphanumeric() || bytes[i - 1] == '_') {
            continue;
        }
        let digits: String = bytes[i + 1..].iter().copied().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            continue;
        }
        let after = bytes.get(i + 1 + digits.len());
        if after.is_some_and(|c| c.is_alphanumeric() || *c == '_') {
            continue;
        }
        if let Ok(n) = digits.parse() {
            out.insert(n);
        }
    }
    out
}

#[test]
fn every_link_between_the_documents_resolves() {
    let Some(dir) = concepts_dir() else { return };
    let mut broken = Vec::new();
    for (name, text) in documents(&dir) {
        // `](SOMETHING.md)` — relative links only; a URL is somebody else's problem.
        for (at, _) in text.match_indices("](") {
            let rest = &text[at + 2..];
            let Some(end) = rest.find(')') else { continue };
            let target = &rest[..end];
            if target.contains("://") || target.starts_with('#') {
                continue;
            }
            let (path, _) = target.split_once('#').unwrap_or((target, ""));
            if path.is_empty() {
                continue;
            }
            if !dir.join(path).exists() && !dir.join("..").join(path).exists() {
                broken.push(format!("{name} -> {path}"));
            }
        }
    }
    assert!(broken.is_empty(), "links that point at nothing: {broken:#?}");
}

#[test]
fn decision_and_risk_numbers_are_contiguous_from_one() {
    let Some(dir) = concepts_dir() else { return };
    for (file, letter, what) in [("DECISIONS.md", 'D', "decision"), ("RISKS.md", 'R', "risk")] {
        let Ok(text) = fs::read_to_string(dir.join(file)) else { continue };
        let numbers = defined(&text, letter);
        assert!(!numbers.is_empty(), "{file} defines no {what} entries");
        let expected: BTreeSet<u32> = (1..=numbers.len() as u32).collect();
        let missing: Vec<_> = expected.difference(&numbers).collect();
        assert!(
            missing.is_empty(),
            "{file} skips {what} numbers {missing:?}; they are stable identifiers, so a \
             gap means an entry was deleted and every citation to it now points at nothing"
        );
    }
}

#[test]
fn every_citation_names_an_entry_that_exists() {
    let Some(dir) = concepts_dir() else { return };
    let decisions = fs::read_to_string(dir.join("DECISIONS.md")).unwrap_or_default();
    let risks = fs::read_to_string(dir.join("RISKS.md")).unwrap_or_default();
    let known_d = defined(&decisions, 'D');
    let known_r = defined(&risks, 'R');

    let mut dangling = Vec::new();
    for (name, text) in documents(&dir) {
        for (letter, known) in [('D', &known_d), ('R', &known_r)] {
            for n in cited(&text, letter) {
                if !known.contains(&n) {
                    dangling.push(format!("{name} cites {letter}{n}"));
                }
            }
        }
    }
    assert!(dangling.is_empty(), "citations with no entry behind them: {dangling:#?}");
}
