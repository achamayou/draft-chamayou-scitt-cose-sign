---
v: 3

title: Multiple-Issuer Statements for the Supply Chain Integrity, Transparency, and Trust (SCITT) Architecture
abbrev: Multiple-Issuer SCITT
docname: draft-chamayou-scitt-cose-sign-latest
date: 2026-07-23
updates: 9943

area: Security
wg: SCITT
kw: Internet-Draft
cat: std
ipr: trust200902
submissiontype: IETF

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
- ins: A. Chamayou
  name: Amaury Chamayou
  org: Microsoft
  email: amaury.chamayou@microsoft.com
  country: United Kingdom

- ins: Y. Deshpande
  name: Yogesh Deshpande
  org: Arm
  email: yogesh.deshpande@arm.com
  country: United Kingdom

normative:
  RFC8610:
  RFC9052:
  RFC9360:
  RFC9597:
  RFC9942:
  RFC9943:

--- abstract

RFC 9943 defines Supply Chain Integrity, Transparency, and Trust (SCITT) Signed Statements and Transparent Statements using `COSE_Sign1`, the single-signer structure defined by Concise Binary Object Representation (CBOR) Object Signing and Encryption (COSE).
This document updates RFC 9943 to permit Statements signed by multiple distinct Issuers to use `COSE_Sign`.
Each signature identifies its own Issuer and Subject.
Receipts remain `COSE_Sign1` structures.

--- middle

# Introduction

Concise Binary Object Representation (CBOR) Object Signing and Encryption (COSE) defines `COSE_Sign`, a structure that supports multiple signatures over the same payload.
This document makes the limited changes needed for multiple Issuers to sign one Statement in the Supply Chain Integrity, Transparency, and Trust (SCITT) architecture defined by {{RFC9943}}.
Each signature carries its own SCITT protected header.
The `COSE_Sign` body protected header MAY carry parameters common to all signatures, but it MUST NOT carry CWT Claims.
All other requirements of {{RFC9943}} continue to apply.

## Motivation

Some Artifacts are accepted only after multiple authorities sign the same Statement.
For example, firmware might require signatures from a component manufacturer, a device manufacturer, and an enterprise deployment authority.
Each Issuer can use its own key, algorithm, certificate chain, Subject, and other protected metadata.

Using separate `COSE_Sign1` objects produces independent Signed Statements that are registered separately.
`COSE_Sign` packages Issuer-specific signatures over one common payload in one registered object.

## Terminology

This document uses the terms "Artifact", "Issuer", "Receipt", "Registration", "Registration Policy", "Signed Statement", "Statement", "Statement Sequence", "Subject", "Transparency Service", and "Transparent Statement" as defined in {{Section 3 of RFC9943}}.
The terms `COSE_Sign`, `COSE_Sign1`, and `COSE_Signature`, and the terms "protected header", "unprotected header", and "payload", are used as defined in {{Sections 3 and 4 of RFC9052}}.

This document uses "joint Statement" for a Signed Statement represented by a tagged `COSE_Sign` and constrained as specified in this document.
Each Issuer signs the common payload and its own protected headers, but does not sign or endorse the other signatures.
A Receipt makes the exact signature set accepted at Registration transparent.

## Requirements Notation

{::boilerplate bcp14-tagged}

# Multiple-Issuer Statements

## Relationship to RFC 9943

This document extends the `Signed_Statement` and `Transparent_Statement` definitions in {{Sections 6 and 7 of RFC9943}}.
A joint Statement uses tagged `COSE_Sign` (CBOR tag 98); the existing single-issuer form continues to use tagged `COSE_Sign1` (CBOR tag 18).
Untagged forms are not permitted.

`Joint_Sign` constrains `COSE_Sign`; it does not define a new COSE message type.
The signing and verification procedures in {{Section 4.4 of RFC9052}} are unchanged.
An implementation of {{RFC9943}} does not necessarily support joint Statements, even though both forms use the same media type.

## Data Model

The following Concise Data Definition Language (CDDL) {{RFC8610}} defines the single-issuer and joint Statement forms.
{{cddl-dependencies}} repeats the definitions imported from {{RFC9052}}, {{RFC9943}}, and {{RFC9360}}.

~~~ cddl
Signed_Statement =
  #6.18(COSE_Sign1) /
  Submitted_Joint_Statement

Transparent_Statement =
  #6.18(Single_Issuer_Transparent_Sign1) /
  Joint_Transparent_Statement

Submitted_Joint_Statement =
  #6.98(Joint_Sign)

Registered_Joint_Statement =
  #6.98(Registered_Joint_Sign)

Joint_Transparent_Statement =
  #6.98(Joint_Transparent_Sign)

Single_Issuer_Transparent_Sign1 =
  Single_Issuer_Transparent_Structure .within COSE_Sign1

Single_Issuer_Transparent_Structure = [
  protected: bstr .cbor Protected_Header,
  unprotected: Receipts_Body_Unprotected_Header,
  payload: bstr / nil,
  signature: bstr
]

Joint_Sign =
  Joint_Sign_Structure .within COSE_Sign

Joint_Sign_Structure = [
  body_protected: Body_Protected,
  body_unprotected:
    Empty_Body_Unprotected_Header /
    Receipts_Body_Unprotected_Header,
  payload: bstr / nil,
  signatures: [2* Joint_Signature]
]

Registered_Joint_Sign =
  Registered_Joint_Structure .within Joint_Sign

Registered_Joint_Structure = [
  body_protected: Body_Protected,
  body_unprotected: Empty_Body_Unprotected_Header,
  payload: bstr / nil,
  signatures: [2* Registered_Joint_Signature]
]

Joint_Transparent_Sign =
  Joint_Transparent_Structure .within Joint_Sign

Joint_Transparent_Structure = [
  body_protected: Body_Protected,
  body_unprotected: Receipts_Body_Unprotected_Header,
  payload: bstr / nil,
  signatures: [2* Registered_Joint_Signature]
]

Joint_Signature =
  Joint_Signature_Structure .within COSE_Signature

Joint_Signature_Structure = [
  sign_protected: bstr .cbor Protected_Header,
  sign_unprotected: Signature_Unprotected_Header,
  signature: bstr
]

Registered_Joint_Signature =
  Registered_Joint_Signature_Structure
    .within Joint_Signature

Registered_Joint_Signature_Structure = [
  sign_protected: bstr .cbor Protected_Header,
  sign_unprotected: {},
  signature: bstr
]

Body_Protected =
  bstr .size 0 / bstr .cbor Body_Protected_Header

; As Protected_Header, but the CWT_Claims header parameter
; (label 15) MUST NOT be present.
Body_Protected_Header = {
  ? &(content_type: 3) => tstr / uint
  * ((int .ne 15) / tstr) => any
}

Signature_Unprotected_Header = {
  * ((int .ne 394) / tstr) => any
}

Empty_Body_Unprotected_Header = {}

Receipts_Body_Unprotected_Header = {
  &(receipts: 394) => [+ bstr .cbor Receipt]
}
~~~
{: #statement-cddl title="Multiple-issuer SCITT statements" sourcecode-name="scitt-multi-issuer.cddl"}

`Single_Issuer_Transparent_Sign1` restates, without changing, the requirement in {{Section 7 of RFC9943}} that a single-issuer Transparent Statement contain only `receipts` in its unprotected header.

## Protected Headers and Issuer Identity

The `COSE_Sign` body protected header MAY be a zero-length byte string or a serialized map conforming to `Body_Protected_Header`.
It carries parameters that apply to the joint Statement as a whole.
It MUST NOT contain the CWT Claims header parameter (label 15); Issuer and Subject identity is scoped to individual signatures.
A verifier MUST reject a joint Statement whose body protected header contains that parameter.

As required by {{Section 6.1 of RFC9943}}, each `COSE_Signature` protected header MUST conform to `Protected_Header` and `CWT_Claims` from Figure 3 in that section, and therefore MUST contain the CBOR Web Token (CWT) Claims header parameter defined in {{Section 2 of RFC9597}} with its own `iss` and `sub` Claims.
Algorithm, key, certificate, Issuer, and Subject metadata is specific to that signature.

The `content_type` parameter describes the common payload.
It MAY appear in the body protected header, in the signature protected headers, or in both.
Where it appears in signature protected headers, it MUST either be absent from every signature or have the same value in every signature.
Where it appears in both the body protected header and a signature protected header, the values MUST be equal.
A `content_type` in the body protected header applies to the joint Statement as a whole and need not be repeated in the signatures.

A joint Statement MUST contain signatures from at least two distinct Issuers.
The Registration Policy MUST define how `iss` values identify Issuers and how aliases are handled.
Unequal `iss` strings alone do not establish distinct Issuer identities.

## Registration and Transparency

A `Submitted_Joint_Statement` may have an empty body unprotected header or one containing only `receipts`.
Signature unprotected headers MAY contain values used for verification or Registration Policy evaluation, but MUST NOT contain `receipts`.

During Registration, the Transparency Service MUST:

1. Verify every signature according to {{Section 4.4 of RFC9052}} using a key authorized for that signature's `iss` value.

2. Apply the required-header and Registration Policy checks from {{Section 6.3 of RFC9943}} to each signature's protected header.

3. Remove all body and signature unprotected values before adding the Statement to a Statement Sequence.

The resulting `Registered_Joint_Statement` has empty body and signature unprotected headers.
Adding one or more Receipts to its body unprotected header produces a `Joint_Transparent_Statement`; its signature unprotected headers remain empty.

A `Joint_Transparent_Statement` may subsequently be submitted to another Transparency Service.
Its existing Receipts are removed during Registration.

`COSE_Sign1` verification and its body `iss` and `sub` Claims are unchanged.

# Security Considerations {#security-considerations}

The security considerations in {{Section 9 of RFC9943}}, {{Section 12 of RFC9052}}, and {{Section 7 of RFC9942}} apply.

Each `COSE_Signature` covers the common payload, the body protected header, its own protected header, and any externally supplied authenticated data used with the signature.
It does not cover the body or signature unprotected headers or other entries in the signatures array.
A holder can therefore reorder or remove signatures, add independently valid signatures, or modify unprotected headers without invalidating the remaining signatures.
In particular, this format does not prove that an Issuer knew of or endorsed another Issuer.

A Transparency Service MUST treat body and signature unprotected header values as unauthenticated.
It MAY use them to locate signature verification material or as Registration Policy input, but it MUST NOT treat them as assertions by an Issuer unless another mechanism authenticates them.

When determining whether a joint Statement has signatures from at least two distinct Issuers, a verifier MUST count distinct, successfully verified, and authorized Issuers after applying its identity and alias rules, rather than counting signatures, keys, or merely unequal `iss` strings.
One authority can control multiple identifiers or keys.

A Receipt binds the complete Statement registered by the Transparency Service, including its signatures array.

# Privacy Considerations

The privacy considerations in {{Section 8 of RFC9943}} apply.
A multiple-issuer Statement exposes every Issuer and Subject identifier in integrity-protected but unencrypted headers.
Combining these identifiers in one Statement can reveal relationships between Issuers and enable correlation across identifier namespaces.

# IANA Considerations

## Media Types Registry

In the "Media Types" registry, IANA is requested to update the `application/scitt-statement+cose` registration as follows:

* Add this document to the "Published specification" field.

* Replace the "Security considerations" field with:

  > {{Section 9.5 of RFC9943}} and {{security-considerations}} of this document.

* Replace the "Interoperability considerations" field with:

  > The mandatory CBOR tags distinguish the `COSE_Sign1` and `COSE_Sign` forms.
  > Implementations that support only the `COSE_Sign1` form specified by {{Sections 6 and 7 of RFC9943}} do not necessarily support the `COSE_Sign` form specified by this document.

* Replace the "Applications that use this media type" field with:

  > Used to provide an identifiable and non-repudiable Statement about an Artifact signed by one or more Issuers.

## CoAP Content-Formats Registry

In the "CoAP Content-Formats" registry, IANA is requested to list this document as an additional reference for ID 277 (`application/scitt-statement+cose`).

No other IANA actions are requested.

--- back

# Repeated CDDL Definitions {#cddl-dependencies}

For completeness, this appendix repeats the structural `COSE_Sign` rules from {{Sections 3 and 4.1 of RFC9052}}; the SCITT rules from Figure 3 in {{Section 6.1 of RFC9943}}; and the certificate rules from {{Section 2 of RFC9360}}.
These rules are unchanged except for comments and formatting.

~~~ cddl
; Repeated from Sections 3 and 4.1 of RFC 9052.
COSE_Sign = [
  Headers,
  payload : bstr / nil,
  signatures : [+ COSE_Signature]
]

COSE_Signature = [
  Headers,
  signature : bstr
]

Headers = (
  protected : empty_or_serialized_map,
  unprotected : header_map
)

header_map = {
  Generic_Headers,
  * label => values
}

empty_or_serialized_map =
  bstr .cbor header_map / bstr .size 0

Generic_Headers = (
  ? 1 => int / tstr,
  ? 2 => [+label],
  ? 3 => tstr / int,
  ? 4 => bstr,
  ? ( 5 => bstr //
      6 => bstr )
)

values = any

; Repeated unchanged from Figure 3 of RFC 9943.
Receipt = #6.18(COSE_Sign1)

COSE_Sign1 = [
  protected   : bstr .cbor Protected_Header,
  unprotected : Unprotected_Header,
  payload     : bstr / nil,
  signature   : bstr
]

Protected_Header = {
  &(CWT_Claims: 15) => CWT_Claims
  ? &(alg: 1) => int
  ? &(content_type: 3) => tstr / uint
  ? &(kid: 4) => bstr
  ? &(x5t: 34) => COSE_CertHash
  ? &(x5chain: 33) => COSE_X509
  * label => any
}

CWT_Claims = {
  &(iss: 1) => tstr
  &(sub: 2) => tstr
  * label => any
}

Unprotected_Header = {
  ? &(x5chain: 33) => COSE_X509
  ? &(receipts: 394) => [+ bstr .cbor Receipt]
  * label => any
}

label = int / tstr

; Repeated from Section 2 of RFC 9360.
COSE_X509 = bstr / [ 2*certs: bstr ]
COSE_CertHash = [ hashAlg: (int / tstr), hashValue: bstr ]
~~~
{: sourcecode-name="scitt-cose-dependencies.cddl"}
