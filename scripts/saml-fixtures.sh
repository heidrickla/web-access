#!/usr/bin/env bash
# Signed SAML responses and IdP metadata for src/saml.rs's tests, signed by xmlsec1 so the verifier
# is checked against an independent signer. Needs xmlsec1 and openssl. The signing keys are thrown
# away: a rerun makes new keys and replaces every fixture.
set -euo pipefail
out="$(cd "$(dirname "$0")/.." && pwd)/tests/fixtures/saml"
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

IDP=https://idp.example.test/adfs/services/trust
ACS=https://access.example.test/api/saml/acs
SP=https://access.example.test/api/saml/metadata
SID=S-1-5-21-1004336348-1177238915-682003330-1105
AT=2026-10-08T12:00:00Z

for k in a b; do
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 36500 \
    -subj "/CN=idp.example.test signing $k" \
    -keyout "$work/key-$k.pem" -out "$work/cert-$k.pem" 2>/dev/null
done
cert() { openssl x509 -in "$work/cert-$1.pem" -outform DER | base64 -w0; }

# A signature template over the element with ID $1, as ADFS and Entra ID send it.
sig() {
  printf '%s' "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><ds:Reference URI=\"#$1\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data/></ds:KeyInfo></ds:Signature>"
}

# $1: the assertion's signature template, or nothing.
assertion() {
  printf '%s' "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a1\" Version=\"2.0\" IssueInstant=\"$AT\"><saml:Issuer>$IDP</saml:Issuer>$1<saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">jdoe@corp.example.test</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData InResponseTo=\"_req1\" NotOnOrAfter=\"2026-10-08T12:05:00Z\" Recipient=\"$ACS\"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"2026-10-08T11:59:00Z\" NotOnOrAfter=\"2026-10-08T13:00:00Z\"><saml:AudienceRestriction><saml:Audience>$SP</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name=\"http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid\"><saml:AttributeValue>$SID</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AuthnStatement AuthnInstant=\"$AT\" SessionIndex=\"_a1\"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>"
}

# $1: the response's signature template, or nothing; $2: the assertion.
response() {
  printf '%s' "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_r1\" Version=\"2.0\" IssueInstant=\"$AT\" Destination=\"$ACS\" InResponseTo=\"_req1\"><saml:Issuer>$IDP</saml:Issuer>$1<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>$2</samlp:Response>"
}

# Signs the first Signature template in $2 with key $1 into $3.
sign() {
  xmlsec1 --sign --privkey-pem "$work/key-$1.pem,$work/cert-$1.pem" \
    --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion \
    --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response \
    --output "$3" "$2"
}

# A signed document without its XML declaration, for embedding.
inner() { sed '1{/^<?xml/d}' "$1"; }

for k in a b; do
  assertion "$(sig _a1)" > "$work/assertion.xml"
  sign "$k" "$work/assertion.xml" "$work/assertion-$k.xml"
done
response "" "$(inner "$work/assertion-a.xml")" > "$out/response-assertion-signed.xml"
response "" "$(inner "$work/assertion-b.xml")" > "$out/response-key-b.xml"
response "$(sig _r1)" "$(inner "$work/assertion-a.xml")" > "$work/both.xml"
sign a "$work/both.xml" "$out/response-both-signed.xml"
response "$(sig _r1)" "$(assertion "")" > "$work/response-only.xml"
sign a "$work/response-only.xml" "$out/response-response-signed.xml"

# $1: the KeyDescriptors.
metadata() {
  printf '%s\n' "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"$IDP\"><md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">$1<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://idp.example.test/adfs/ls/\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.example.test/adfs/ls/\"/></md:IDPSSODescriptor></md:EntityDescriptor>"
}
key() {
  printf '%s' "<md:KeyDescriptor use=\"$1\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>$(cert "$2")</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
}
# Key b is the encryption key here, which must not verify a signature.
metadata "$(key signing a)$(key encryption b)" > "$out/idp-metadata.xml"
# A certificate rollover: the new key listed first.
metadata "$(key signing b)$(key signing a)" > "$out/idp-metadata-rollover.xml"
ls -l "$out"
