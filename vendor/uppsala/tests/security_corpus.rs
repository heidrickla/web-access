//! Security & adversarial corpus runner.
//!
//! Drives the payloads assembled under `test-data/corpus/security/` by
//! `scripts/fetch_corpus.sh`. Three families:
//!
//! - `recurse/` — libxml2's canonical entity-expansion DoS corpus (billion
//!   laughs, quadratic blowup, parameter laughs, external-entity variants).
//! - `xxe/` — generated XXE / SSRF file-read payloads.
//! - `roundtrip/` — namespace/mixed-content edge cases for the
//!   parse→serialize→re-parse stability invariant.
//!
//! Every test is a **static-input** check. uppsala never resolves external
//! entities and never opens files or sockets, so the invariants are:
//! parsing terminates in bounded time, never panics, never amplifies past the
//! entity caps, and never surfaces the contents of an external `.ent`/`.dtd`
//! file (which would only be possible via a file read).
//!
//! The corpus is excluded from the published crate; when it is absent the
//! suite prints a notice and passes (mirrors `w3c_xmlconf.rs`).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use uppsala::parse;

/// Wall-clock ceiling for a single hostile parse. The property under test is
/// *termination* (the entity/length caps fail closed), not raw speed: a genuine
/// billion-laughs hang would run for minutes or never. The bound is generous
/// because these run in an unoptimized `cargo test` (debug) build, where the
/// legitimately O(n²) quadratic-blowup payloads (`lol_long_name` in particular)
/// take about 5-6 seconds before the cap fires on local runs. Ten seconds gives
/// enough slack for debug/CI noise while still catching hangs much faster than a
/// broad 30-second ceiling.
const PARSE_CEILING: Duration = Duration::from_secs(10);

fn corpus_dir() -> Option<PathBuf> {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test-data")
        .join("corpus")
        .join("security");
    if base.exists() {
        Some(base)
    } else {
        eprintln!("security corpus not found, skipping (run scripts/fetch_corpus.sh)");
        None
    }
}

/// List files in `dir` with the given extension, sorted for determinism.
fn files_with_ext(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some(ext))
            .collect(),
        Err(_) => Vec::new(),
    };
    out.sort();
    out
}

/// Parse `xml`, returning whether it succeeded and how long it took. A panic
/// inside `parse` would fail the enclosing test directly, which is what we
/// want — the harness treats "did not panic and returned within the ceiling"
/// as the pass condition.
fn timed_parse(xml: &str) -> (bool, Duration) {
    let start = Instant::now();
    let ok = parse(xml).is_ok();
    (ok, start.elapsed())
}

// ─── Entity-expansion DoS corpus (libxml2 test/recurse) ────────────────────

/// Every `lol_*` / `huge_dtd` payload must terminate well within the ceiling
/// and must not amplify: either the parser rejects it (entity cap fires) or it
/// returns a *bounded* tree. Nothing hangs, OOMs, or panics.
#[test]
fn recurse_corpus_is_bounded_and_never_hangs() {
    let Some(base) = corpus_dir() else { return };
    let dir = base.join("recurse");
    if !dir.exists() {
        eprintln!("recurse corpus absent (needs ../libxml2), skipping");
        return;
    }

    let payloads: Vec<PathBuf> = files_with_ext(&dir, "xml")
        .into_iter()
        .filter(|p| {
            let n = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            n.starts_with("lol_") || n == "huge_dtd.xml"
        })
        .collect();
    assert!(
        !payloads.is_empty(),
        "recurse corpus present but no lol_*/huge_dtd payloads found"
    );

    let mut checked = 0usize;
    for path in &payloads {
        let xml = fs::read_to_string(path).unwrap();
        let (ok, elapsed) = timed_parse(&xml);
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(
            elapsed < PARSE_CEILING,
            "{name}: parse took {elapsed:?} (>= {PARSE_CEILING:?}) — DoS regression"
        );
        if ok {
            // If it parsed, the tree must be bounded: the caps guarantee the
            // expanded content cannot exceed the 1 MiB entity budget by much.
            let doc = parse(&xml).unwrap();
            if let Some(root) = doc.document_element() {
                let len = doc.text_content_deep(root).len();
                assert!(
                    len < 4 << 20,
                    "{name}: parsed OK but expanded to {len} bytes — amplification regression"
                );
            }
        }
        checked += 1;
        eprintln!(
            "recurse {name}: {} in {elapsed:?}",
            if ok { "parsed (bounded)" } else { "rejected" }
        );
    }
    eprintln!("recurse corpus: {checked} payloads bounded, none hung");
}

/// The internal-subset billion-laughs / quadratic payloads must be **rejected**
/// by the entity-expansion budget — they reference an entity that expands past
/// 1 MiB, so a well-formed-but-unbounded expansion is a fail-closed error.
#[test]
fn recurse_internal_laughs_rejected() {
    let Some(base) = corpus_dir() else { return };
    let dir = base.join("recurse");
    if !dir.exists() {
        return;
    }
    // These define their entities in the *internal* subset (or inline), so
    // uppsala actually performs the expansion and the cap must fire.
    let internal = [
        "lol_classic.xml",
        "lol_ig_attr.xml",
        "lol_ig_content.xml",
        "lol_long_name.xml",
        "lol_long_value.xml",
    ];
    for name in internal {
        let path = dir.join(name);
        if !path.exists() {
            continue;
        }
        let xml = fs::read_to_string(&path).unwrap();
        let (ok, elapsed) = timed_parse(&xml);
        assert!(
            !ok,
            "{name}: internal entity blow-up should be rejected by the expansion cap"
        );
        assert!(
            elapsed < PARSE_CEILING,
            "{name}: rejection took {elapsed:?}"
        );
    }
}

/// External general/parameter-entity variants reference `.ent`/`.dtd` files
/// that sit right next to the payload. uppsala never resolves external
/// entities, so a file read would inject the fragment's sentinel text
/// (`some internal data`) into the tree. Assert it never appears — proof of
/// no file read.
#[test]
fn recurse_external_entities_not_read() {
    let Some(base) = corpus_dir() else { return };
    let dir = base.join("recurse");
    if !dir.exists() {
        return;
    }
    // Sentinel unique to the external `.ent` fragments (ga.ent/pa.ent).
    const SENTINEL: &str = "some internal data";
    let external = [
        "lol_eg.xml",
        "lol_ep.xml",
        "lol_ip_content.xml",
        "lol_ip_value.xml",
        "huge_dtd.xml",
    ];
    for name in external {
        let path = dir.join(name);
        if !path.exists() {
            continue;
        }
        let xml = fs::read_to_string(&path).unwrap();
        let (_ok, elapsed) = timed_parse(&xml);
        assert!(elapsed < PARSE_CEILING, "{name}: took {elapsed:?}");
        // Whether the parse succeeds or fails, the external fragment must not
        // have been fetched: its content cannot appear in any serialization.
        if let Ok(doc) = parse(&xml) {
            let serialized = doc.to_xml();
            assert!(
                !serialized.contains(SENTINEL),
                "{name}: external entity content leaked into the tree — a file was read!"
            );
        }
    }
}

/// The Sebastian Pipping "parameter laughs" payload (internal parameter-entity
/// DoS) must terminate cleanly — reject or bounded, never a hang.
#[test]
fn recurse_parameter_laughs_terminates() {
    let Some(base) = corpus_dir() else { return };
    let path = base.join("recurse").join("lol_param.xml");
    if !path.exists() {
        return;
    }
    let xml = fs::read_to_string(&path).unwrap();
    let (_ok, elapsed) = timed_parse(&xml);
    assert!(
        elapsed < PARSE_CEILING,
        "lol_param.xml: parameter-laughs took {elapsed:?} — DoS regression"
    );
}

/// The benign `good.xml` / `good_attr.xml` controls (bounded entity fan-out,
/// below the cap) must still parse — proof the cap does not over-reject.
#[test]
fn recurse_benign_controls_parse() {
    let Some(base) = corpus_dir() else { return };
    let dir = base.join("recurse");
    if !dir.exists() {
        return;
    }
    for name in ["good.xml", "good_attr.xml"] {
        let path = dir.join(name);
        if !path.exists() {
            continue;
        }
        let xml = fs::read_to_string(&path).unwrap();
        let (ok, elapsed) = timed_parse(&xml);
        assert!(ok, "{name}: bounded benign entity fan-out must still parse");
        assert!(elapsed < PARSE_CEILING, "{name}: took {elapsed:?}");
    }
}

// ─── XXE / SSRF file-read payloads (generated) ─────────────────────────────

/// Each XXE payload names a `file://`, `http://`, or `php://` resource via an
/// external entity. uppsala must not resolve any of them: parse either rejects
/// or leaves the entity unexpanded, and the named resource's content never
/// appears. Static inputs — nothing here is fetched.
#[test]
fn xxe_payloads_perform_no_external_io() {
    let Some(base) = corpus_dir() else { return };
    let dir = base.join("xxe");
    if !dir.exists() {
        return;
    }
    let payloads = files_with_ext(&dir, "xml");
    assert!(!payloads.is_empty(), "xxe corpus present but empty");
    for path in &payloads {
        let name = path.file_name().unwrap().to_str().unwrap();
        let xml = fs::read_to_string(path).unwrap();
        let (_ok, elapsed) = timed_parse(&xml);
        assert!(elapsed < PARSE_CEILING, "{name}: took {elapsed:?}");
        if let Ok(doc) = parse(&xml) {
            // If the external entity were resolved, /etc/passwd content
            // (`root:`) or metadata would land in the root text. It must not.
            let serialized = doc.to_xml();
            assert!(
                !serialized.contains("root:x:0:0"),
                "{name}: /etc/passwd content leaked — XXE file read happened!"
            );
        }
        eprintln!("xxe {name}: no external resolution");
    }
}

// ─── Round-trip stability (namespace / mixed-content edge cases) ───────────

/// The SAML-bypass class: `parse(serialize(parse(x)))` must be identical to
/// `parse(x)`. We assert the serialization reaches a fixpoint after one round
/// trip, so namespace prefixes and expanded names cannot drift.
#[test]
fn roundtrip_corpus_is_stable() {
    let Some(base) = corpus_dir() else { return };
    let dir = base.join("roundtrip");
    if !dir.exists() {
        return;
    }
    let payloads = files_with_ext(&dir, "xml");
    assert!(!payloads.is_empty(), "roundtrip corpus present but empty");
    for path in &payloads {
        let name = path.file_name().unwrap().to_str().unwrap();
        let xml = fs::read_to_string(path).unwrap();
        let doc1 = parse(&xml).unwrap_or_else(|e| panic!("{name}: first parse failed: {e:?}"));
        let ser1 = doc1.to_xml();
        let doc2 = parse(&ser1).unwrap_or_else(|e| panic!("{name}: re-parse failed: {e:?}"));
        let ser2 = doc2.to_xml();
        assert_eq!(
            ser1, ser2,
            "{name}: serialization not a fixpoint — round-trip drift (SAML-bypass class)"
        );
        eprintln!("roundtrip {name}: stable");
    }
}
