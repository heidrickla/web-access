//! Gzips the page assets and names each by a hash of its content, for `web.rs` to serve with an
//! ETag. Done here so serving costs nothing and the compressed bytes match the embedded ones.

use std::io::Write;
use std::path::Path;

const FILES: &[&str] = &[
    "index.html",
    "admin.html",
    "app.css",
    "app.js",
    "admin.js",
    "theme.js",
    "saml-done.js",
    "ironrdp_web.js",
    "ironrdp_web_bg.wasm",
    "notices.html",
    "notices-client.html",
];

/// FNV-1a, 64 bits: a cache validator, not a security check.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}

fn main() {
    let out = std::env::var("OUT_DIR").expect("OUT_DIR");
    let mut table = String::from(
        "/// (file, its gzip, the ETag of each), from build.rs.\npub const PACKED: &[(&str, &[u8], &str, &str)] = &[\n",
    );
    for file in FILES {
        let source = Path::new("web").join(file);
        println!("cargo:rerun-if-changed={}", source.display());
        let raw = std::fs::read(&source).expect("read a web asset");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        gz.write_all(&raw).expect("compress");
        let gz = gz.finish().expect("compress");
        let hash = fnv1a(&raw);
        let packed = Path::new(&out).join(format!("{file}.gz"));
        std::fs::write(&packed, gz).expect("write the compressed asset");
        table.push_str(&format!(
            "    ({file:?}, include_bytes!({:?}), \"\\\"{hash:016x}\\\"\", \"\\\"{hash:016x}-gz\\\"\"),\n",
            packed.display().to_string(),
        ));
    }
    table.push_str("];\n");
    std::fs::write(Path::new(&out).join("packed.rs"), table).expect("write packed.rs");
}
