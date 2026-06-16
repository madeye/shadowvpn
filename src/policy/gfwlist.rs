//! Domain-suffix matching for **gfwlist mode**.
//!
//! A [`GfwList`] is a set of domain *suffixes* (e.g. `google.com`,
//! `twitter.com`). A queried name matches when it equals one of the suffixes or
//! is a subdomain of one — so `www.google.com` and `a.b.google.com` both match
//! the suffix `google.com`. Matched domains are resolved via the clean upstream
//! and their addresses are routed through the tunnel; everything else is left to
//! the direct path.
//!
//! # File format
//!
//! One domain per line. Blank lines and comments are ignored, where a comment
//! is a line starting with `#` or `!` (the latter is the AutoProxy/gfwlist
//! comment marker). A leading `.` or `*.` and a trailing `.` are stripped, and
//! names are lower-cased, so `*.example.com`, `.example.com`, and `example.com`
//! are all stored as the suffix `example.com`. This is the plain-text domain
//! list shape produced by tools like `gfwlist2dnsmasq`, not the base64 AutoProxy
//! blob.

use std::collections::HashSet;
use std::path::Path;

/// A set of domain suffixes to route through the tunnel.
#[derive(Debug, Default, Clone)]
pub struct GfwList {
    /// Normalized suffixes (lower-case, no leading/trailing dot).
    suffixes: HashSet<String>,
}

impl GfwList {
    /// Build a list from an iterator of raw domain lines.
    ///
    /// Lines are normalized and filtered exactly as described in the
    /// [module docs](self); comments and blanks are dropped.
    pub fn from_lines<I, S>(lines: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut suffixes = HashSet::new();
        for line in lines {
            if let Some(domain) = normalize(line.as_ref()) {
                suffixes.insert(domain);
            }
        }
        Self { suffixes }
    }

    /// Load a list from a newline-delimited file.
    pub fn load(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(Self::from_lines(text.lines()))
    }

    /// Number of stored suffixes.
    pub fn len(&self) -> usize {
        self.suffixes.len()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.suffixes.is_empty()
    }

    /// Whether `domain` should be routed through the tunnel: true when the name
    /// equals or is a subdomain of any stored suffix.
    ///
    /// Matching walks the name from the most specific parent up to the TLD, so
    /// `a.b.example.com` tests `a.b.example.com`, `b.example.com`,
    /// `example.com`, and `com` against the suffix set.
    pub fn matches(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return false;
        }
        // Test the full name, then each parent suffix.
        let bytes = domain.as_bytes();
        if self.suffixes.contains(&domain) {
            return true;
        }
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'.' {
                // Safe: we split on an ASCII '.' boundary.
                if self.suffixes.contains(&domain[i + 1..]) {
                    return true;
                }
            }
        }
        false
    }
}

/// Normalize a raw line into a stored suffix, or `None` if it is a
/// comment/blank.
fn normalize(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
        return None;
    }
    let line = line
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if line.is_empty() {
        None
    } else {
        Some(line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> GfwList {
        GfwList::from_lines([
            "# a comment",
            "! autoproxy comment",
            "",
            "google.com",
            "*.twitter.com",
            ".wikipedia.org",
            "EXAMPLE.NET.",
        ])
    }

    #[test]
    fn normalizes_and_skips_comments() {
        let l = sample();
        assert_eq!(l.len(), 4);
        assert!(l.matches("google.com"));
        assert!(l.matches("twitter.com"));
        assert!(l.matches("wikipedia.org"));
        assert!(l.matches("example.net"));
    }

    #[test]
    fn matches_subdomains_only() {
        let l = sample();
        assert!(l.matches("www.google.com"));
        assert!(l.matches("a.b.c.google.com"));
        assert!(l.matches("WWW.Google.Com")); // case-insensitive
        assert!(l.matches("api.twitter.com."));
        assert!(!l.matches("google.com.cn")); // not a subdomain of google.com
        assert!(!l.matches("notgoogle.com"));
        assert!(!l.matches("com"));
        assert!(!l.matches("baidu.com"));
        assert!(!l.matches(""));
    }
}
