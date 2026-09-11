//! Shared XML reading helpers for the two Maven documents this crate
//! parses — the POM ([`super::pom`]) and `maven-metadata.xml`
//! ([`super::metadata`]).
//!
//! Both readers are **byte-level pull parsers**: element names are matched
//! as raw bytes and only the text of the handful of elements a reader
//! actually consumes is decoded. That is what lets a POM whose
//! `<description>` carries non-UTF-8 bytes still yield its
//! `<dependencies>` — the invalid bytes are never decoded because no
//! reader asks for them.
//!
//! Namespaces are matched on the **local name**. Maven POMs declare
//! `xmlns="http://maven.apache.org/POM/4.0.0"` as a default namespace and
//! Maven Central's `maven-metadata.xml` declares none at all; Maven
//! Resolver itself parses both namespace-agnostically, so matching the
//! local name is the behaviour that agrees with the ecosystem rather than
//! a shortcut.

use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesRef, BytesStart, BytesText, Event};
use quick_xml::Reader;

/// Hard ceiling on element nesting. A real POM nests to single digits and
/// the deepest legitimate shape in the wild is a plugin `<configuration>`
/// tree; 256 is orders of magnitude above that, so tripping it means the
/// document is a nesting bomb rather than a Maven document.
pub(crate) const MAX_ELEMENT_DEPTH: usize = 256;

/// The element's local name (namespace prefix stripped) as an owned
/// `String`. Element names are XML `Name` productions, which the readers
/// here only ever compare against ASCII literals; a name carrying
/// non-UTF-8 bytes therefore cannot match any path of interest and is
/// rendered lossily rather than failing the whole parse.
pub(crate) fn local_name_of(start: &BytesStart<'_>) -> String {
    String::from_utf8_lossy(start.local_name().as_ref()).into_owned()
}

/// Decoded text of a character-data event, EOL-normalised per XML 1.0.
///
/// `None` when the bytes are not valid UTF-8 — the caller treats that
/// element as carrying no value rather than failing the document, so an
/// undecodable element the reader does not need cannot abort it.
pub(crate) fn decode_text(text: &BytesText<'_>) -> Option<String> {
    text.xml10_content().ok().map(std::borrow::Cow::into_owned)
}

/// Resolve a general reference (`&amp;`, `&#x41;`) to the text it stands
/// for.
///
/// quick-xml surfaces references as their own event rather than expanding
/// them into the surrounding text, so a reader that ignores this event
/// would silently drop characters from a value. Character references and
/// the five predefined entities resolve; anything else (which requires a
/// DTD-declared entity, something no Maven document uses) yields `None`
/// and the caller drops the reference.
pub(crate) fn resolve_reference(reference: &BytesRef<'_>) -> Option<String> {
    if let Ok(Some(ch)) = reference.resolve_char_ref() {
        return Some(ch.to_string());
    }
    let name = reference.decode().ok()?;
    resolve_predefined_entity(&name).map(str::to_string)
}

/// Collect the trimmed text of every element at the exact element `path`
/// (local names, from the document root), in document order.
///
/// **Degrade-open.** A malformed document yields whatever was collected
/// before the parse error rather than an error: every caller is a
/// best-effort discovery reader whose failure mode must be "no upstream
/// signal this tick", not "abort".
///
/// Repeated and empty values are preserved — de-duplication and filtering
/// are the caller's policy, not this helper's.
pub(crate) fn collect_text_at_path(bytes: &[u8], path: &[&str]) -> Vec<String> {
    let mut reader = Reader::from_reader(bytes);
    let mut buf: Vec<u8> = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut text = String::new();
    let mut out: Vec<String> = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) | Err(_) => break,
            Ok(Event::Start(start)) => {
                if stack.len() >= MAX_ELEMENT_DEPTH {
                    break;
                }
                stack.push(local_name_of(&start));
                text.clear();
            }
            Ok(Event::Empty(start)) => {
                // An empty element is a start immediately followed by an
                // end, carrying no text.
                if stack.len() >= MAX_ELEMENT_DEPTH {
                    break;
                }
                stack.push(local_name_of(&start));
                if stack == path {
                    out.push(String::new());
                }
                stack.pop();
                text.clear();
            }
            Ok(Event::End(_)) => {
                if stack == path {
                    out.push(text.trim().to_string());
                }
                stack.pop();
                text.clear();
            }
            Ok(Event::Text(chunk)) if stack == path => {
                if let Some(decoded) = decode_text(&chunk) {
                    text.push_str(&decoded);
                }
            }
            Ok(Event::CData(chunk)) if stack == path => {
                if let Ok(decoded) = chunk.decode() {
                    text.push_str(&decoded);
                }
            }
            Ok(Event::GeneralRef(reference)) if stack == path => {
                if let Some(resolved) = resolve_reference(&reference) {
                    text.push_str(&resolved);
                }
            }
            Ok(_) => {}
        }
        buf.clear();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &[&str] = &["metadata", "versioning", "versions", "version"];

    #[test]
    fn collects_values_in_document_order() {
        let xml = br#"<metadata><versioning><versions>
            <version>1.0</version><version>2.0</version><version>1.5</version>
        </versions></versioning></metadata>"#;
        assert_eq!(collect_text_at_path(xml, PATH), ["1.0", "2.0", "1.5"]);
    }

    #[test]
    fn ignores_same_named_elements_at_a_different_path() {
        // `<version>` also appears directly under `<metadata>` in real
        // A-level documents; only the exact path is collected.
        let xml = br#"<metadata><version>9.9</version><versioning><versions>
            <version>1.0</version>
        </versions></versioning></metadata>"#;
        assert_eq!(collect_text_at_path(xml, PATH), ["1.0"]);
    }

    #[test]
    fn resolves_entities_and_cdata_and_trims() {
        let xml = br#"<metadata><versioning><versions>
            <version>  1.0&#45;rc  </version>
            <version><![CDATA[2.0-final]]></version>
            <version>a&amp;b</version>
        </versions></versioning></metadata>"#;
        assert_eq!(
            collect_text_at_path(xml, PATH),
            ["1.0-rc", "2.0-final", "a&b"]
        );
    }

    #[test]
    fn empty_element_yields_an_empty_value() {
        let xml = br#"<metadata><versioning><versions>
            <version/><version>1.0</version>
        </versions></versioning></metadata>"#;
        assert_eq!(collect_text_at_path(xml, PATH), ["", "1.0"]);
    }

    #[test]
    fn matches_the_local_name_under_a_default_namespace() {
        let xml = br#"<metadata xmlns="http://maven.apache.org/METADATA/1.1.0">
            <versioning><versions><version>1.0</version></versions></versioning>
        </metadata>"#;
        assert_eq!(collect_text_at_path(xml, PATH), ["1.0"]);
    }

    #[test]
    fn matches_the_local_name_under_an_explicit_prefix() {
        let xml = br#"<m:metadata xmlns:m="urn:x"><m:versioning><m:versions>
            <m:version>1.0</m:version>
        </m:versions></m:versioning></m:metadata>"#;
        assert_eq!(collect_text_at_path(xml, PATH), ["1.0"]);
    }

    #[test]
    fn degrades_open_on_a_truncated_document() {
        // Everything read before the parse error is kept.
        let xml = br#"<metadata><versioning><versions>
            <version>1.0</version><version>2.0</version"#;
        assert_eq!(collect_text_at_path(xml, PATH), ["1.0"]);
    }

    #[test]
    fn non_xml_bytes_yield_nothing() {
        assert!(collect_text_at_path(&[0x1F, 0x8B, 0x08, 0x00], PATH).is_empty());
    }

    #[test]
    fn comments_inside_the_target_element_do_not_end_it() {
        let xml = br#"<metadata><versioning><versions>
            <version>1.<!-- inline -->0</version>
        </versions></versioning></metadata>"#;
        assert_eq!(collect_text_at_path(xml, PATH), ["1.0"]);
    }

    #[test]
    fn nesting_bomb_stops_at_the_depth_ceiling() {
        let mut xml = Vec::new();
        for _ in 0..(MAX_ELEMENT_DEPTH + 10) {
            xml.extend_from_slice(b"<a>");
        }
        // The walk breaks out at the ceiling rather than growing the stack.
        assert!(collect_text_at_path(&xml, PATH).is_empty());
    }

    #[test]
    fn undecodable_text_in_the_target_element_is_dropped_not_fatal() {
        // An invalid UTF-8 byte inside the collected element drops that
        // chunk; the surrounding document still parses.
        let mut xml = Vec::from(&b"<metadata><versioning><versions><version>"[..]);
        xml.push(0xFF);
        xml.extend_from_slice(
            b"</version><version>1.0</version></versions></versioning></metadata>",
        );
        assert_eq!(collect_text_at_path(&xml, PATH), ["", "1.0"]);
    }
}
