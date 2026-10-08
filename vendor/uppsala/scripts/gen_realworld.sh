#!/bin/sh
# gen_realworld.sh <dest-dir>
# Generate one minimal-but-valid sample per XML dialect (§4 of other_xml.md).
# Files are deliberately small with a known shape so realworld_corpus.rs can
# assert deterministic node counts. Locally generated => no third-party
# license attaches. Called by fetch_corpus.sh.
set -eu

DEST=${1:?usage: gen_realworld.sh <dest-dir>}
mk() { d=$(dirname "$DEST/$1"); mkdir -p "$d"; cat > "$DEST/$1"; }

# ── Feeds ──────────────────────────────────────────────────────────────────
mk rss/rss.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>Example Feed</title>
    <link>https://example.org/</link>
    <atom:link href="https://example.org/rss.xml" rel="self"/>
    <description><![CDATA[A <b>sample</b> feed & test]]></description>
    <item><title>First</title><guid>1</guid></item>
    <item><title>Second</title><guid>2</guid></item>
    <item><title>Third</title><guid>3</guid></item>
  </channel>
</rss>
EOF

mk atom/atom.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xml:lang="en" xml:base="https://example.org/">
  <title>Example</title>
  <updated>2026-01-01T00:00:00Z</updated>
  <entry><title>One</title><id>urn:1</id></entry>
  <entry><title>Two</title><id>urn:2</id></entry>
</feed>
EOF

# ── Web services ────────────────────────────────────────────────────────────
mk soap/soap.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <env:Header/>
  <env:Body>
    <m:GetPrice xmlns:m="urn:example:stock">
      <m:symbol xsi:type="xsd:string">ACME</m:symbol>
    </m:GetPrice>
  </env:Body>
</env:Envelope>
EOF

# ── Identity ────────────────────────────────────────────────────────────────
mk saml/metadata.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="https://idp.example.org/idp">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://idp.example.org/sso"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="https://idp.example.org/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
EOF

# ── Documents ───────────────────────────────────────────────────────────────
# XHTML with a DOCTYPE but no DTD-defined named entities (uppsala does not
# resolve external DTDs), so only numeric character references are used.
mk xhtml/page.xhtml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
  <head><title>Doc</title></head>
  <body>
    <p>First &#160;para</p>
    <p>Second para</p>
  </body>
</html>
EOF

# ── Graphics ────────────────────────────────────────────────────────────────
mk svg/shapes.svg <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
     width="100" height="100" viewBox="0 0 100 100">
  <rect x="0" y="0" width="10" height="10"/>
  <rect x="20" y="0" width="10" height="10"/>
  <circle cx="50" cy="50" r="5"/>
  <a xlink:href="https://example.org/"><rect x="0" y="80" width="5" height="5"/></a>
</svg>
EOF

# ── Geo ─────────────────────────────────────────────────────────────────────
mk gpx/track.gpx <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<gpx version="1.1" creator="uppsala" xmlns="http://www.topografix.com/GPX/1/1">
  <trk><name>Trail</name><trkseg>
    <trkpt lat="59.85" lon="17.63"><ele>10</ele></trkpt>
    <trkpt lat="59.86" lon="17.64"><ele>12</ele></trkpt>
    <trkpt lat="59.87" lon="17.65"><ele>14</ele></trkpt>
  </trkseg></trk>
</gpx>
EOF

mk kml/places.kml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <Placemark>
      <name>A</name>
      <description><![CDATA[<b>bold</b> & raw]]></description>
      <Point><coordinates>17.6,59.8,0</coordinates></Point>
    </Placemark>
    <Placemark>
      <name>B</name>
      <Point><coordinates>17.7,59.9,0</coordinates></Point>
    </Placemark>
  </Document>
</kml>
EOF

# ── Config ──────────────────────────────────────────────────────────────────
mk pom/pom.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency><groupId>a</groupId><artifactId>x</artifactId><version>1</version></dependency>
    <dependency><groupId>b</groupId><artifactId>y</artifactId><version>2</version></dependency>
  </dependencies>
</project>
EOF

# Apple plist: DOCTYPE with Apple's public/system DTD id, no body entities.
mk plist/config.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Name</key><string>Demo</string>
    <key>Enabled</key><true/>
    <key>Count</key><integer>3</integer>
  </dict>
</plist>
EOF

# ── Publishing ──────────────────────────────────────────────────────────────
mk sitemap/sitemap.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.org/</loc><priority>1.0</priority></url>
  <url><loc>https://example.org/a</loc></url>
  <url><loc>https://example.org/b</loc></url>
  <url><loc>https://example.org/c</loc></url>
</urlset>
EOF

# A minimal sitemap schema so realworld_corpus.rs exercises the XSD-validation
# path (assertion 5) on a real-world namespaced shape.
mk sitemap/schema.xsd <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           targetNamespace="http://www.sitemaps.org/schemas/sitemap/0.9"
           xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
           elementFormDefault="qualified">
  <xs:element name="urlset">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="url" maxOccurs="unbounded">
          <xs:complexType>
            <xs:sequence>
              <xs:element name="loc" type="xs:anyURI"/>
              <xs:element name="lastmod" type="xs:string" minOccurs="0"/>
              <xs:element name="changefreq" type="xs:string" minOccurs="0"/>
              <xs:element name="priority" type="xs:decimal" minOccurs="0"/>
            </xs:sequence>
          </xs:complexType>
        </xs:element>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>
EOF

# ── Reports ─────────────────────────────────────────────────────────────────
mk junit/results.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="3" failures="1">
  <testsuite name="suite" tests="3" failures="1">
    <testcase classname="A" name="ok1" time="0.01"/>
    <testcase classname="A" name="ok2" time="0.02"/>
    <testcase classname="B" name="bad"><failure message="boom">trace</failure></testcase>
  </testsuite>
</testsuites>
EOF

# ── Office ──────────────────────────────────────────────────────────────────
mk ooxml/document.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>Hello</w:t></w:r></w:p>
    <w:p><w:r><w:t xml:space="preserve"> world </w:t></w:r></w:p>
    <w:sectPr/>
  </w:body>
</w:document>
EOF

printf '  generated %s realworld samples\n' "$(find "$DEST" -name '*.xml' -o -name '*.svg' -o -name '*.kml' -o -name '*.gpx' -o -name '*.xhtml' -o -name '*.plist' | wc -l)"
