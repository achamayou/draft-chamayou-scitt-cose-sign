---
v: 3

title: Multiple-Issuer SCITT Statements with COSE_Sign
abbrev: Multi-Issuer SCITT
docname: draft-chamayou-scitt-cose-sign-00
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

RFC 9943 defines single-issuer SCITT Signed Statements and Transparent
Statements using COSE_Sign1.  This document updates RFC 9943 to additionally
permit COSE_Sign, with each signature identifying its own issuer and subject.
Receipts remain COSE_Sign1.

--- middle

# Introduction

COSE_Sign supports multiple signatures over the same payload.  This document
makes the limited changes needed for multiple issuers to sign one Statement in
the SCITT architecture defined by {{RFC9943}}.  Each signature carries its own
SCITT protected header.  The COSE_Sign body protected header is empty.  All
other requirements of RFC 9943 continue to apply.

## Motivation

Some artifacts are accepted only after multiple authorities sign the same
Statement.  For example, firmware might require signatures from a component
manufacturer, a device manufacturer, and an enterprise deployment authority.
Each Issuer can use its own key, algorithm, certificate chain, subject, and
other protected metadata.

Separate COSE_Sign1 objects represent independent Signed Statements and
registrations.  COSE_Sign packages issuer-specific signatures over one common
payload in one registered object.

This document uses "joint Statement" in that limited sense.  Each Issuer signs
the common payload and its own protected headers, but does not sign or endorse
the other signatures.  A Receipt makes the exact signature set accepted at
Registration transparent.

## Requirements Notation

{::boilerplate bcp14-tagged}

# Multiple-Issuer Statements

This document updates Sections 6 and 7 of RFC 9943.  Where those sections
require a Signed Statement or Transparent Statement to be a tagged
COSE_Sign1, a tagged COSE_Sign is also permitted for a multiple-issuer
Statement subject to this section.  Untagged forms are not permitted.

`Multi_Issuer_Sign` is a constrained subtype of `COSE_Sign`, not a new COSE
message type.  It uses CBOR tag 98 and the COSE_Sign signature creation and
verification procedures in Section 4.4 of RFC 9052 without modification.

The CDDL {{RFC8610}} below defines the extension.  {{cddl-dependencies}}
repeats its dependencies from {{RFC9052}}, RFC 9943, and {{RFC9360}}.

~~~ cddl
Signed_Statement =
  #6.18(COSE_Sign1) /
  #6.98(Multi_Issuer_Signed_Statement)

Transparent_Statement =
  #6.18(COSE_Sign1) /
  #6.98(Multi_Issuer_Transparent_Statement)

Submitted_Multi_Issuer_Statement =
  #6.98(Multi_Issuer_Submission)

Multi_Issuer_Sign =
  Multi_Issuer_Sign_Structure .within COSE_Sign

Multi_Issuer_Sign_Structure = [
  body_protected: bstr .size 0,
  body_unprotected:
    Empty_Body_Unprotected_Header /
    Receipts_Body_Unprotected_Header,
  payload: bstr / nil,
  signatures: [2* Multi_Issuer_Signature]
]

Multi_Issuer_Submission =
  Multi_Issuer_Submission_Structure .within Multi_Issuer_Sign

Multi_Issuer_Submission_Structure = [
  body_protected: bstr .size 0,
  body_unprotected: Empty_Body_Unprotected_Header,
  payload: bstr / nil,
  signatures: [2* Multi_Issuer_Signature]
]

Multi_Issuer_Signed_Statement =
  Multi_Issuer_Signed_Structure .within Multi_Issuer_Sign

Multi_Issuer_Signed_Structure = [
  body_protected: bstr .size 0,
  body_unprotected: Empty_Body_Unprotected_Header,
  payload: bstr / nil,
  signatures: [2* Registered_Multi_Issuer_Signature]
]

Multi_Issuer_Transparent_Statement =
  Multi_Issuer_Transparent_Structure .within Multi_Issuer_Sign

Multi_Issuer_Transparent_Structure = [
  body_protected: bstr .size 0,
  body_unprotected: Receipts_Body_Unprotected_Header,
  payload: bstr / nil,
  signatures: [2* Registered_Multi_Issuer_Signature]
]

Multi_Issuer_Signature =
  Multi_Issuer_Signature_Structure .within COSE_Signature

Multi_Issuer_Signature_Structure = [
  sign_protected: bstr .cbor Protected_Header,
  sign_unprotected: Signature_Unprotected_Header,
  signature: bstr
]

Registered_Multi_Issuer_Signature =
  Registered_Multi_Issuer_Signature_Structure
    .within Multi_Issuer_Signature

Registered_Multi_Issuer_Signature_Structure = [
  sign_protected: bstr .cbor Protected_Header,
  sign_unprotected: {},
  signature: bstr
]

Signature_Unprotected_Header = {
  * ((int .ne 394) / tstr) => any
}

Empty_Body_Unprotected_Header = {}

Receipts_Body_Unprotected_Header = {
  &(receipts: 394) => [+ bstr .cbor Receipt]
}
~~~
{: #statement-cddl title="Multiple-issuer SCITT statements" sourcecode-name="scitt-multi-issuer.cddl"}

The COSE_Sign body protected header MUST be encoded as a zero-length byte
string.  The body therefore contains no protected header parameters and no
statement-wide Issuer or Subject.

Each COSE_Signature protected header independently follows `Protected_Header`
and `CWT_Claims` from Figure 3 of RFC 9943.  Each signature contains its own
`iss` and `sub` Claims in the CWT Claims header parameter {{RFC9597}}.
Algorithm, key, certificate, Issuer, and Subject metadata are
signature-specific.  The `content_type` parameter describes the common
payload; it MUST either be absent from every signature or have the same value
in every signature.  At least two distinct `iss` values MUST be present.

`Submitted_Multi_Issuer_Statement` is the form accepted as Registration input.
Its body unprotected header is empty, but its signature unprotected headers MAY
contain values used for signature verification or Registration Policy
evaluation.  The `receipts` parameter MUST NOT occur in a signature
unprotected header.  Before adding the Statement to a Statement Sequence, the
Transparency Service MUST remove all signature unprotected values to produce
`Multi_Issuer_Signed_Statement`.  Consequently, the registered Statement has
empty body and signature unprotected headers.

A `Multi_Issuer_Transparent_Statement` is a registered Statement with one or
more Receipts in its body unprotected header.  That header MUST contain only
the `receipts` parameter (label 394).  Signature unprotected headers MUST
remain empty.

A Transparency Service that accepts COSE_Sign MUST verify every signature
according to Section 4.4 of RFC 9052 using a key authorized for that
signature's `iss` value.  It MUST apply the required-header and Registration
Policy checks of RFC 9943 separately to each signature's protected header,
including its `sub` value.  Its Registration Policy MAY additionally require
a specific set or threshold of distinct issuers or issuer-subject pairs.
COSE_Sign1 verification and its body `iss` and `sub` Claims are unchanged.

# Security Considerations

The security considerations of {{RFC9943}}, {{RFC9052}}, and {{RFC9942}}
apply.

Each COSE_Signature covers the common payload, the empty body protected header,
and its own protected header.  It does not cover other entries in the
signatures array.  A holder can therefore add or remove independently valid
signatures without invalidating the remaining signatures.  In particular,
this format does not prove that an Issuer knew of or endorsed another Issuer.

A policy requiring a fixed issuer set or threshold MUST define that
requirement independently of the signatures array and MUST count distinct,
successfully verified `iss` values rather than array entries.  This document
does not provide atomic "all issuers or none" semantics before Registration.

A Receipt binds the complete Statement registered by the Transparency Service,
including its signatures array.  A Relying Party MUST verify both the Receipt
and its applicable issuer policy before relying on the registered signature
set.

# Privacy Considerations

The privacy considerations of RFC 9943 apply.  A multiple-issuer Statement
exposes every issuer and subject identifier in protected, but unencrypted,
headers.

# IANA Considerations

IANA is requested to add this document as an additional reference for the
`application/scitt-statement+cose` media type and for CoAP Content-Format 277.
In that media type registration, "signed by an Issuer" is replaced by "signed
by one or more Issuers".
No new media type, Content-Format, CBOR tag, or COSE header parameter is
registered.

--- back

# Repeated CDDL Definitions {#cddl-dependencies}

For completeness, this appendix repeats the structural `COSE_Sign` rules from
Sections 3 and 4.1 of RFC 9052; the SCITT rules from Figure 3 of RFC 9943; and
the certificate rules from Section 2 of RFC 9360.  These rules are unchanged
except for comments and formatting.

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
