---
stand_alone: true
ipr: trust200902
docname: draft-ietf-cose-x509-08
cat: std
consensus: 'true'
submissiontype: IETF
pi:
  toc: 'yes'
  symrefs: 'yes'
  sortrefs: 'yes'
  comments: 'yes'
title: 'CBOR Object Signing and Encryption (COSE): Header parameters for carrying
  and referencing X.509 certificates'
abbrev: COSE X.509
area: Security
author:
- ins: J. Schaad
  name: Jim Schaad
  org: August Cellars
  email: ietf@augustcellars.com
informative:
  RFC8446:
  I-D.ietf-tls-dtls13: # to be replaced by RFC9147
  RFC8551:
  RFC2585:
  I-D.ietf-lake-edhoc:
  RFC8392:
  RFC8610:
  RFC3986:
  I-D.ietf-anima-constrained-voucher:
  RFC6838:
  RFC8613:
  RFC2634:
normative:
  RFC5280:
  RFC8152:
  RFC8949:

--- abstract


The CBOR Signing And Encrypted Message (COSE) structure uses references to
keys in general.
For some algorithms, additional properties are defined which carry parameters
relating to keys as needed.
The COSE Key structure is used for transporting keys outside of COSE messages.
This document extends the way that keys can be identified and transported
by providing attributes that refer to or contain X.509 certificates.

--- to_be_removed_note_Contributing_to_this_document

The source for this draft is being maintained in GitHub.
Suggested changes should be submitted as pull requests at [](https://github.com/cose-wg/X509).
Instructions are on that page as well.
Editorial changes can be managed in GitHub, but any substantial issues need
to be discussed on the COSE mailing list.

--- middle

# Introduction {#introduction}

In the process of writing {{RFC8152}}, the working group discussed X.509 certificates {{RFC5280}} and decided that no use cases were presented that showed a need to support
certificates.
Since that time, a number of cases have been defined in which X.509 certificate
support is necessary, and by implication, applications will need a documented
and consistent way to handle such certificates.
This document defines a set of attributes that will allow applications to
transport and refer to X.509 certificates in a consistent manner.

<!--  JLS - Robin did you really mean to just refer to version -00?  -->In some of these cases, a constrained device is being deployed in the context
of an existing X.509 PKI: for example, {{I-D.ietf-anima-constrained-voucher}} describes a device enrollment solution that relies on the presence of a factory-installed
certificate on the device.
The {{I-D.ietf-lake-edhoc}} draft was also written with the idea that long term certificates could be
used to provide for authentication of devices, and uses them to establish
session keys.
Another possible scenario is the use of COSE as the basis for a secure messaging
application.
This scenario assumes the presence of long term keys and a central authentication
authority.
Basing such an application on public key certificates allows it to make use
of well established key management disciplines.

## Requirements Terminology {#requirements-terminology}

{::boilerplate bcp14-tagged}

# X.509 COSE Header Parameters

The use of X.509 certificates allows for an existing trust infrastructure
to be used with COSE.
This includes the full suite of enrollment protocols, trust anchors, trust
chaining and revocation checking that have been defined over time by the
IETF and other organizations.
The key structures that have been defined in COSE currently do not support
all of these properties, although some may be found in COSE Web Tokens (CWT) {{RFC8392}}.

It is not necessarily expected that constrained devices themselves will evaluate
and process X.509 certificates:
it is perfectly reasonable for a constrained device to be provisioned with
a certificate that it subsequently provides to a relying party - along with
a signature or encrypted message - on the assumption that the relying party
is not a constrained device, and is capable of performing the required certificate
evaluation and processing.
It is also reasonable that a constrained device would have the hash of a
certificate associated with a public key and be configured to use a public
key for that thumbprint, but without performing the certificate evaluation
or even having the entire certificate. In any case, there still needs to
be an entity that is responsible for handling the possible certificate revocation.

Parties that intend to rely on the assertions made by a certificate
obtained from any of these methods still need to validate it.
This validation can be done according to the PKIX rules in {{RFC5280}}
or by using a different trust structure, such as a trusted certificate
distributor for self-signed certificates.
The PKIX validation includes matching against the trust anchors configured
for the application.
These rules apply when the validation succeeds in a single step as well as
when certificate chains need to be built.
If the application cannot establish trust in the certificate, the public
key contained in the certificate cannot be used for cryptographic operations.

The header parameters defined in this document are:


x5bag:
: This header parameter contains a bag of X.509 certificates.
  The set of certificates in this header parameter is unordered and may contain
  self-signed certificates. Note that there could be duplicate certificates.
  The certificate bag can contain certificates which are completely extraneous
  to the message.
  (An example of this would be where a signed message is being used to transport
  a certificate containing a key agreement key.)
  As the certificates are unordered, the party evaluating the signature will
  need to be capable of building the certificate path as necessary.
  That party will also have to take into account that the bag may not contain
  the full set of certificates needed to build any particular chain.

  The trust mechanism MUST process any certificates in this parameter as untrusted
  input.
  The presence of a self-signed certificate in the parameter MUST NOT cause
  the update of the set of trust anchors without some out-of-band confirmation.
  As the contents of this header parameter are untrusted input, the header
  parameter can be in either the protected or unprotected header bucket. Sending
  the header parameter in the unprotected header bucket allows an intermediary
  to remove or add certificates.

  <!--  Robin
      [Is the point being made here that the header is incidental to any trust processing that is done on the basis of the certificates in the bag?
      If so, I suggest the following text:
      "As the trust mechanisms in operation here do not depend on the header element itself, the header attribute MAY be either protected or unprotected. "]

        JLS:
        Does this read better?
       -->

  The end-entity certificate MUST be integrity protected by COSE. This can
  e.g. be done by sending the header parameter in the protected header, sending
  a x5bag in the unprotected header combined with a x5t in the protected header,
  or including the end-entity certificate in the external_aad.

  This header parameter allows for a single X.509 certificate or a bag of X.509
  certificates to be carried in the message.

  * If a single certificate is conveyed, it is placed in a CBOR byte string.

  * If multiple certificates are conveyed, a CBOR array of byte strings is used,
    with each certificate being in its own byte string.


x5chain:
: This header parameter contains an ordered array of X.509 certificates.
  The certificates are to be ordered starting with the certificate containing
  the end-entity key followed by the certificate which signed it and so on.
  There is no requirement for the entire chain to be present in the element
  if there is reason to believe that the relying party already has, or can
  locate the missing certificates.
  This means that the relying party is still required to do path building,
  but that a candidate path is proposed in this header parameter.

  <!--  Robin
      [Is the point being made here that the header is incidental to any trust processing that is done on the basis of the certificates in the bag?
      If so, I suggest the following text:
      "As the trust mechanisms in operation here do not depend on the header element itself, the header attribute MAY be either protected or unprotected. "]
       -->

  The trust mechanism MUST process any certificates in this parameter as untrusted
  input.
  The presence of a self-signed certificate in the parameter MUST NOT cause
  the update of the set of trust anchors without some out-of-band confirmation.
  As the contents of this header parameter are untrusted input, the header
  parameter can be in either the protected or unprotected header bucket. Sending
  the header parameter in the unprotected header bucket allows an intermediary
  to remove or add certificates.

  The end-entity certificate MUST be integrity protected by COSE. This can
  e.g. be done by sending the header parameter in the protected header, sending
  a x5chain in the unprotected header combined with a x5t in the protected
  header, or including the end-entity certificate in the external_aad as.

  This header parameter allows for a single X.509 certificate or a chain of
  X.509 certificates to be carried in the message.

  * If a single certificate is conveyed, it is placed in a CBOR byte string.

  * If multiple certificates are conveyed, a CBOR array of byte strings is used,
    with each certificate being in its own byte string.


x5t:
: This header parameter identifies the end-entity X.509 certificate by a hash
  value (a thumbprint).
  The 'x5t' header parameter is represented as an array of two elements.
  The first element is an algorithm identifier which is an integer or a string
  containing the hash algorithm identifier corresponding to either the Value
  (integer) or Name (string) column of the algorithm registered in the "COSE
  Algorithms" registry [](https://www.iana.org/assignments/cose/cose.xhtml#algorithms).
  The second element is a binary string containing the hash value computed
  over the DER encoded certificate.

  As this header parameter does not provide any trust, the header parameter
  can be in either a protected or unprotected header bucket.

  The identification of the end-entity certificate MUST be integrity protected
  by COSE. This can be done by sending the header parameter in the protected
  header or including the end-entity certificate in the external_aad.

  The 'x5t' header parameter can be used alone or together with the 'x5bag',
  'x5chain', or 'x5u' header parameters to provide integrity protection of
  the end-entity certificate.

  For interoperability, applications which use this header parameter MUST support
  the hash algorithm 'SHA-256', but can use other hash algorithms. This requirement
  allows for different implementations to be configured to use an interoperable
  algorithm, but does not preclude the use (by prior agreement) of other algorithms.

  RFC Editor please remove the following two paragraphs:

  During AD review, a question was raised about how effective the previous
  statement is in terms of dealing with a MTI algorithm.
  There needs to be some type of arrangement between the parties to agree that
  a specific hash algorithm is going to be used in computing the thumbprint.
  Making it a MUST use would make that true, but it then means that agility
  is going to be very difficult.

  The worry is that while SHA-256 may be mandatory, if a sender supports SHA-256
  but only sends SHA-512 then the recipient which only does SHA-256 would not
  be able to use the thumbprint.
  In that case both applications would conform to the specification, but still
  not be able to inter-operate.

x5u:
: This header parameter provides the ability to identify an X.509 certificate
  by a URI {{RFC3986}}. It contains a CBOR text string.
  The referenced resource can be any of the following media types:

  * application/pkix-cert {{RFC2585}}

  * application/pkcs7-mime; smime-type="certs-only" {{RFC8551}}

  * application/cose-x509 {{media-type}}
  * application/cose-x509; usage=chain {{media-type}}

  <!--               <t>application/pem-certificate-chain <xref target="I-D.ietf-acme-acme"/></t>  -->

  When the application/cose-x509 media type is used, the data is a
  CBOR sequence of single-entry COSE_X509 structures (encoding "bstr").
  If the parameter "usage" is
  set to "chain", this sequence indicates a certificate chain.

  The end-entity certificate MUST be integrity protected by COSE. This can
  e.g. be done by sending the x5u in the unprotected or protected header combined
  with a x5t in the protected header, or including the end-entity certificate
  in the external_aad. As the end-entity certificate is integrity protected
  by COSE, the URI does not need to provide any protection.

  If a retrieved certificate does not chain to an existing trust anchor, that
  certificate MUST NOT be trusted unless the URI provided integrity protection
  and server authentication and the server is configured as trusted to provide
  new trust anchors or if an out-of-band confirmation can be received for trusting
  the retrieved certificate. In case an HTTP or CoAP GET request is used to
  retrieve a certificate, TLS {{RFC8446}}, DTLS {{I-D.ietf-tls-dtls13}} or
  {{RFC8613}} SHOULD be used.

The header parameters are used in the following locations:


* COSE_Signature and COSE_Sign1 objects: in these objects they identify the
  certificate to be used for validating the signature.

* COSE_recipient objects: in this location they identify the certificate for
  the recipient of the message.

The labels assigned to each header parameter can be found in the following
table.

| Name | Label | Value Type | Description |
| x5bag | 32 | COSE_X509 | An unordered bag of X.509 certificates |
| x5chain | 33 | COSE_X509 | An ordered chain of X.509 certificates |
| x5t | 34 | COSE_CertHash | Hash of an X.509 certificate |
| x5u | 35 | uri | URI pointing to an X.509 certificate |
{: #Tags title='X.509 COSE Header Parameters' align='center'}

Below is an equivalent CDDL {{RFC8610}} description of the text above.

~~~~ CDDL
COSE_X509 = bstr / [ 2*certs: bstr ]
COSE_CertHash = [ hashAlg: (int / tstr), hashValue: bstr ]
~~~~

The content of the bstr are the bytes of a DER encoded certificate.


# X.509 certificates and static-static ECDH

The header parameters defined in the previous section are used to identify
the recipient certificates for the ECDH key agreement algorithms.
In this section we define the algorithm specific parameters that are used
for identifying or transporting the sender's key for static-static key agreement
algorithms.

These attributes are defined analogously to those in the previous section.
There is no definition for the certificate bag, as the same attribute would
be used for both the sender and recipient certificates.

<!--  Robin
        [I think this needs a little more explanation, for example (if correct):
        "For static-static ECDH key agreement, the message MUST use one of the following 3 header attributes;
        the x5bag attribute is not valid in this use case, because... ?x5bag implies that the sender and recipient may use different attributes?."

        JLS
        No that is not correct.  If doing static-static, then there are two different certificates that need to be identified, that of the sender
        and that of the recipient.  The recipient certificate would be identified by the x5c or x5t properties.  The sender certificate
        would be defined by one of these certificates.  If you used x5t and x5t-sender, but include both certificates in the bag of certificates.
        Normally only the sender certificates would be included as it is assumed that the recipient can identify its certificate without being
        given the actual certificate.

        How much of this needs to be added above?
         -->


x5chain-sender:
: This header parameter contains the chain of certificates starting with the
  sender's key exchange certificate.
  The structure is the same as 'x5chain'.

x5t-sender:
: This header parameter contains the hash value for the sender's key exchange
  certificate.
  The structure is the same as 'x5t'.

x5u-sender:
: This header parameter contains a URI for the sender's key exchange certificate.
  The structure and processing are the same as 'x5u'.

| Name           | Label | Type          | Algorithm                                                                          | Description                                  |
| x5t-sender     | TBD   | COSE_CertHash | ECDH-SS+HKDF-256, ECDH-SS+HKDF-512, ECDH-SS+A128KW, ECDH-SS+A192KW, ECDH-SS+A256KW | Thumbprint for the sender's X.509 certificate |
| x5u-sender     | TBD   | uri           | ECDH-SS+HKDF-256, ECDH-SS+HKDF-512, ECDH-SS+A128KW, ECDH-SS+A192KW, ECDH-SS+A256KW | URI for the sender's X.509 certificate       |
| x5chain-sender | TBD   | COSE_X509     | ECDH-SS+HKDF-256, ECDH-SS+HKDF-512, ECDH-SS+A128KW, ECDH-SS+A192KW, ECDH-SS+A256KW | static key X.509 certificate chain           |
{: #Tags2 title='Static ECDH Algorithm Values' align='center'}

# IANA Considerations {#iana-considerations}

## COSE Header Parameter Registry {#cose-header-key-table}

IANA is requested to register the new COSE Header parameters in {{Tags}} in the "COSE Header Parameters" registry.
The "Value Registry" field is empty for all of the items.
For each item, the 'Reference' field points to this document.


## COSE Header Algorithm Parameter Registry

IANA is requested to register the new COSE Header Algorithm parameters in {{Tags2}} in the "COSE Header Algorithm Parameters" registry.
For each item, the 'Reference' field points to this document.

## Media Type application/cose-x509 {#media-type}

When the application/cose-x509 media type is used, the data is a
CBOR sequence of single-entry COSE_X509 structures (encoding "bstr").
If the parameter "usage" is
set to "chain", this sequence indicates a certificate chain.

IANA is requested to register the following media type {{RFC6838}}:

Type name:
: application

Subtype name:
: cose-x509

Required parameters:
: N/A

Optional parameters:
: usage

  * Can be absent to provide no further information about the intended
    meaning of the order in the CBOR sequence of certificates.
  * Can be set to "chain" to indicate that the sequence of data items is
    to be interpreted as a certificate chain.

Encoding considerations:
: binary

Security considerations:
: See the Security Considerations section of RFCthis.

Interoperability considerations:
: N/A

Published specification:
: RFCthis

Applications that use this media type:
: Applications that employ COSE and use X.509 as a certificate type.

Fragment identifier considerations:
: N/A

Additional information:
: Deprecated alias names for this type:
  : N/A

  Magic number(s):
  : N/A

  File extension(s):
  : N/A

  Macintosh file type code(s):
  : N/A

Person & email address to contact for further information:
   iesg@ietf.org

Intended usage:
: COMMON

Restrictions on usage:
: N/A

Author:
: COSE WG

Change controller:
: IESG

Provisional registration? (standards tree only):
: no



# Security Considerations {#security-considerations}

Establishing trust in a certificate is a vital part of processing.
A major component of establishing trust is determining what the set of trust
anchors are for the process.
A new self-signed certificate appearing on the client cannot be a trigger
to modify the set of trust anchors, because a well-defined trust-establishment
process is required.
One common way for a new trust anchor to be added (or removed) from a device
is by doing a new firmware upgrade.

<!--  Robin
        [Is this true, and if so, does it follow from the preceding statements, or is it a discrete assertion?
        It's not clear to me that adding new trust anchors to constrained devices is the only relevant use case here,
        or that it is the only instance of establishing trust in a certificate.
        Traversing a certificate chain or issuing an OCSP request may be other instances.]

        JLS
        I was trying to deal just with trust anchors - so I have modified the text to reflect that.
         -->

In constrained systems, there is a trade-off between the order of checking
the signature and checking the certificate for validity.
Validating certificates can require that network resources be accessed in
order to get revocation information or retrieve certificates during path
building.
The resulting network access can consume power and network bandwidth.
On the other hand, if the certificates are validated after the signature
is validated, an oracle can potentially be built based on detecting the network
resources which is only done if the signature validation passes.
In any event, both the signature and certificate validation MUST be completed
successfully before acting on any requests.

Unless it is known that the CA required proof-of-possession of the subject's
private key to issue an end-entity certificate, the end-entity certificate
MUST be integrity protected by COSE.  Without proof-of-possession, an attacker
can trick the CA to issue an identity-misbinding certificate with someone
else's "borrowed" public-key but with a different subject.  A MITM attacker
can then perform an identity-misbinding attack by replacing the real end-entity
certificate in COSE with such an identity-misbinding certificate.

End-entity X.509 certificates contain identities that a passive on-path attacker
eavesdropping on the conversation can use to identify and track the subject.
COSE does not provide identity protection by itself and the x5t and x5u
header parameters are just alternative permanent identifiers and can also
be used to track the subject. To provide identity protection, COSE can be
sent inside another security protocol providing confidentiality.

Before using the key in a certificate, the key MUST be checked against the
algorithm to be used and any algorithm specific checks need to be made.
These checks can include validating that points are on curves for elliptical
curve algorithms, and that sizes of RSA keys are of an acceptable size.
The use of unvalidated keys can lead either to loss of security or excessive
consumption of resources (for example using a 200K RSA key).

<!--  Robin
        Two questions:
        (1) are there any other important checks that should be noted here, or is the  COSE algs document the authoritative guide?
        (2) how does use of unvalidated keys lead to excessive resource consumption?

        (1) The COSE algorithm draft(s) have the be the authoritative guides because the set is going to be algorithm specific.
        (2) The easiest example would be an RSA key which is 16K bits long.  Doing the match on this will take a significantly longer amount of time
            and use a significantly amount of memory than what would be used by a 2048-bit RSA key.
       -->

When processing the x5u header parameter the security considerations
of {{RFC3986}} and specifically those defined in {{Section 7.1 of RFC3986}} also apply.

Regardless of the source, certification path validation is an important part
of establishing trust in a certificate. {{Section 6 of RFC5280}}
provides guidance for the path validation. The security considerations
of {{RFC5280}} are also important for the correct usage of this document.

Protecting the integrity of the x5bag, x5chain and x5t contents by placing them
in the protected header bucket MAY mitigate some risks of a misbehaving
certificate authority (c.f. {{Section 5.1 of RFC2634}}).

The security of the algorithm used for 'x5t' does not affect the security
of the system as this header parameter selects which certificate that is
already present on the system should be used, but it does not provide any
trust.


--- back

# Acknowledgements
{:unnumbered}
