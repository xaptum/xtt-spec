---
coding: utf-8

title: The Xaptum Trusted Transit (XTT) Protocol Version 1.0
abbrev: XTT
docname: draft-xaptum-xtt-latest
category: info

ipr: noDerivativesTrust200902
area: General
workgroup: 
keyword: Internet-Draft

stand_alone: yes
pi:
  rfcedstyle: no
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  text-list-symbols: -o*+
  docmapping: yes
author:
  -
        ins: Z. Beckwith
        name: Zane Beckwith
        organization: Xaptum, Inc.
        email: zane.beckwith@xaptum.com
  -
        ins: D. Bild
        name: David R. Bild
        organization: Xaptum, Inc.
        email: david.bild@xaptum.com

normative:
  RFC5116:
  RFC5869:
  RFC7539:
  RFC7693:
  RFC7748:
  
  SHS:
       title: Secure Hash Standard
       date: 2012-03
       author:
         org: National Institute of Standards and Technology
       seriesinfo:
         NIST: FIPS PUB 180-4

informative:
  RFC2119:
  RFC5246:
  RFC6347:

  MINIMALT:
       title: "MinimalLT: Minimal-latency Networking Through Better Security"
       date: 2013-11
       author:
       - 
         ins: W. Petullo
       - 
         ins: X. Zhang
       -
         ins: J. Solworth
       -
         ins: D. Bernstein
       -
         ins: T. Lange

--- abstract

This document specifies version 1.0 of the Xaptum Trusted Transit
(XTT) protocol for securing the Internet of Things (IoT). It provides
scalable identitiy provisioning, device authentication, and data
integrity and confidentiality.

--- middle

# Introduction

DISCLAIMER: This is a WIP draft and has not yet seen significant
security analysis.

(TODO) (1 par.) Describe primary goals of XTT

- Identity Provisioning: (TODO) (1 par.) describe desired provisioning
  properites

- Authenticiation: (TODO) (1 par.) describe desired authentication
  properties

- Integrity: (TODO) (1 par.) describe desired integrity properties

- Confidentiality: (TODO) (1 par.) describe desired confidentiality
  properties
  
- IP-address Mobility: (TODO) (1 par.) describe desired mobility properties

- DoS Protection: (TODO) (1 par.) describe desired DoS protection desires

(TODO) (1 par.) Describe attack/threat model. What view/control does
the attacker have, e.g., RFC3552.

XTT consists of three primary components:

- An identity provisioning protocol
  ({{identity-provisioning-protocol}}) that (TODO) (1 par.) describe
  this protocol

- A session establishment protocol
  ({{session-establishment-protocol}}) that (TODO) (1 par.) describe
  this protocol

- A record protocol ({{record-protocol}}) that (TODO) (1 par.)
  describe this protocol

## Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in RFC
2119 {{RFC2119}}.

The following terms are used:

client: (TODO) (1 sent.)

endpoint: (TODO) (1 sent.)

handshake: (TODO) (1 sent.)

identity: (TODO) (1 sent.)

receiver: (TODO) (1 sent.)

sender: (TODO) (1 sent.)

server: (TODO) (1 sent.)

session: (TODO) (1 sent.)

## Security Requirements for the IoT

(TODO) How IoT security differs from old world. What are the unique
requirements.

### Differences from (D)TLS

(TODO) (1 list) what (D)TLS doesn't offer that IoT requires

### Differences from QUIC

(TODO) (1 list) what QUIC doesn't offer that IoT requires

### Differences from MinimaLT

(TODO) (1 list) what MinimalLT doesn't offer that IoT requires

# Protocol Overview

(TODO) (1-2 para.) Outline the flow from provisioning, to
establishment, to communication.

(TODO) (1 para.) Discuss protocol error handling


~~~
      Client                                                Server
Key  ^ ClientInit
Exch | + key_share*
     | + signature_algorithms*
     | + psk_key_exchange_modes*
     v + pre_shared_key*          -------> 
                                                      ServerHello ^ Key
                                                     + key_share* | Exch
                                                + pre_shared_key* v
                                  <-------
     ^ {Certificate*}
Auth | {CertificateVerify*}
     V {Finished}                 ------->
       [Application Data]         <------>     [Application Data]

            +  Indicates noteworty
               something
              
            *  Indicates optional
               something
              
            {} Indicates messages protected using
               something
               
            [] Indicates messages protected using
               something
~~~
{: #xtt-provisioning title="Message flow for XTT Identity Provisioning Handshake"}


(TODO) (1 diagram). Basic flow.

# Identity Provisioning Protocol

(TODO)


# Session Establishment Protocol

(TODO)


# Record Protocol

(TODO)

--- back

# State Machine

This section provides a summary of the legal state machine transitions
for the client and server handshakes.  State names (in all capitals,
e.g., START) have no formal meaning, but are provided for ease of
comprehension. Messages which are sent only sometimes are indicated in
[].

## Identity Provisioning Handshake

### Client

(TODO)

### Server

(TODO)

## Session Establishment Handshake

### Client

(TODO)

### Server

(TODO)

# Presentation Language

## Miscellaneous
Comments begin with "/\*" and end with "\*/".

To indicate the number of bytes taken up in the byte stream
by a type or value, the expression `sizeof(value-or-type)` is used.

Optional components are denoted by enclosing them in "[[ ]]" double
brackets.

## Definition of Byte
One byte is defined to be 8 bits.
Multiple-byte data items are concatenations of bytes, from left to right, from top to
bottom.

## Byte Arrays
A byte-array is a single-dimensional array of bytes of given fixed length.
The syntax for specifying a new type, `Tp`, that is a
byte-array of length `n` is

~~~
byte Tp[n];
~~~

Here, `Tp` occupies `n` bytes in the data stream.
The length of the vector is not included in the
encoded stream.

An anonymous byte array is specified by not including a new
type name: `byte[n]` indicates space of n bytes in the byte stream.
This is useful for constructed and variant types.

Unless defined as a numeric data type, the bytes comprising
a byte-array are not to be interpreted by the protocol in any way.

## Numeric Data
A type defined as an n-byte numeric value
indicates that the byte stream
is interpreted (using C notation) as:

~~~
numeric_value = (byte[0] << 8*(n-1)) | (byte[1] << 8*(n-2)) |
        ... | byte[n-1];
~~~

This byte ordering for multi-byte values is the commonplace network
byte order or big-endian format.
The pre-defined numeric types uint8, uint16, uint32, and uint64 are defined as

~~~
byte uint8[1];
byte uint16[2];
byte uint32[4];
byte uint64[8];
~~~

For example, the uint32 value given by the bytestream
`01 02 03 04` is interpreted as the decimal value 16909060.

## Enumerateds
To indicate a type that may take values only from
a fixed set of possible values, a new type may be defined
as of type `enum`.
Each definition of an enumerated type is a different type.
Only enumerateds of the same type may be assigned or compared.
Every element of an enumerated must be assigned a value.

The possible values of an enumerated type are specified in this
document using numeric values.
To indicate how to interpret a value of an enumerated type,
and to indicate how much space in the byte stream is occupied
by an enumerated type, the definition of the enumerated type includes
the underlying numeric type used to define its values.

Implementations that receive a value of an enumerated type that is not
in the set of possible values for that type MUST reject the containing
message and handle the error as specified for that message type.

The following example defines an enumerated type called Color
that has three possible values, which are represented in the byte stream
as uint16 values (thus a value of type Color occupies 2 bytes in the byte stream)

~~~
enum : uint16 {
        Red(0x1234),
        Green(9),
        Blue(60000)
} Color;
~~~

The names of the elements of an enumerated type are scoped within
the defined type, and a reference in this document
to the value of a name is always
given by the fully-qualified form `Type.Name`.
Thus a reference to the `Color` value `Blue` from above is given by `Color.Blue`.

## Constructed Types
Complex types may be constructed from primitive types, using
the `struct` construction.
Each constructed type defines a new type.

The following example defines a constructed type called `T`, which comprises
two subfields `f1` and `f2`

~~~
struct {
        T1 f1;
        T2 f2;
} T;
~~~

A value of type `T` would occupy a total of `sizeof(T1) + sizeof(T2)` bytes in the byte stream.

Subfields of a constructed type are referenced in this document by
`Type.subfield` when referring to the field in the general type `Type`,
and by `name.subfield` when referring to the field in a specific value named `name`.
Thus, the value of the subfield `f2`
in a value called `foo` of type `T`, from the example above, would be
referenced as `foo.f1`.

## AEAD-Encrypted Constructed Types
Encryption and authentication of all messages in this protocol
are done using Authenticated Encryption with Additional Data (AEAD) {{RFC5116}}.
To indicate that a constructed type is processed using an AEAD algorithm,
the following notation is used:

~~~
aead_struct<key_set>(
        addl1;
        addl2;
        ...
        addlN;
)[
        enc1;
        enc2;
        ...
        encN;
] T;
~~~

In this example, the type `T` consists of the unencrypted subfields `addl1`
through `addlN`, and the encrypted subfields `enc1` through `encN`.
The keys (encryption key, authentication key, and nonce) used is given by `key_set`.
The entire struct is authenticated.
Note that the total length in the byte stream of a value of type `T` is
the size of an authentication tag (determined by the chosen AEAD algorithm)
in addition to the sum of the sizes of its subfields.

## Constants
Fields and variables may be assigned a fixed value using `=`.
In the following example, all values of type `T` would always have
`T.c` equal to `Color.Blue`

~~~
struct {
        Color c = Color.Blue;
        T2 f2;
} T;
~~~

## Variants
Defined structures may have variants based on some knowledge that is
available within the environment.
The selector must be an enumerated
type that defines the possible variants the structure defines.
There must be a case arm for every element of the enumeration declared in
the select.
Case arms have limited fall-through: if two case arms
follow in immediate succession with no fields in between, then they
both contain the same fields.

The mechanism by which the variant is selected at runtime is not
prescribed by the presentation language.

For example:

~~~
uint8 SubT1;
uint16 SubT2;
struct {
        select (color_in) {
                case Color.Red:
                        SubT1;
                case Color.Green:
                case Color.Blue:
                        SubT2;
        } variant_field;
} VariantStruct;
~~~

In this example, it is assumed the creation of a value
of type `VariantStruct` requires the input of a parameter
called `color_in` of type `Color`.
When creating a value of type VariantStruct with name S,
if `color_in` is `Red` then the subfield `S.variant_field`
is of type `SubT1`.
Alternatively, if `color_in` is either `Green` or `Blue`,
`S.variant_field` is of type `SubT2`.
Note that the size of the type `VariantStruct` depends on the value
of `color_in` at the time of construction.

# Protocol Data Structures and Constant Values

This section describes protocol types and constants.

## Common Message Header

~~~
enum : uint8 {
        client_init(0x01),
        server_init_and_attest(0x02),
        id_clientattest_noresponse_payload_ip(0x11),
        id_clientattest_response_nopayload_ip(0x12),
        id_clientattest_response_payload_ip(0x13),
        id_clientattest_response_nopayload_noip(0x14),
        id_clientattest_response_payload_noip(0x15),
        id_serverfinished(0x16),
        session_clientattest_noresponse_payload_ip(0x21),
        session_clientattest_response_nopayload_ip(0x22),
        session_clientattest_response_payload_ip(0x23),
        session_clientattest_response_nopayload_noip(0x24),
        session_clientattest_response_payload_noip(0x25),
        session_serverfinished(0x26),
        record_regular(0x31),
        alert(0x41)
} MsgType;
~~~

~~~
enum : uint8 {
        one(1)
} Version;
~~~

## Handshakes

~~~
enum : uint16 {
        x25519_epid2_chacha20poly1305_sha512(1),
        x25519_epid2_chacha20poly1305_blake2b(2),
        x25519_epid2_aes256gcm_sha512(3),
        x25519_epid2_aes256gcm_blake2b(4),
        x25519_epid2_null_sha512(5),
        x25519_epid2_null_blake2b(6)
} SuiteSpec;
~~~

~~~
byte SessionIDSeed[8];
~~~

~~~
byte SigningNonce[32];
~~~

~~~
byte ServerCookie[130];
~~~

~~~
byte ClientID[16];
~~~

~~~
byte LongtermSecret[64];
~~~

~~~
select(dh_algorithm) {
        case x25519_epid2_chacha20poly1305_sha512:
        case x25519_epid2_chacha20poly1305_blake2b:
        case x25519_epid2_aes256gcm_sha512:
        case x25519_epid2_aes256gcm_blake2b:
        case x25519_epid2_null_sha512:
        case x25519_epid2_null_blake2b:
                byte[32];
} DHKeyShare;
~~~

~~~
enum : uint8 {
        Ed25519(1)
} ServerSignatureType;
~~~

~~~
select(server_signature_algorithm) {
        case Ed25519:
                byte[32];
} ServerSignature;
~~~

### DAA Types

~~~
select(dh_algorithm) {
        case x25519_epid2_chacha20poly1305_sha512:
        case x25519_epid2_chacha20poly1305_blake2b:
        case x25519_epid2_aes256gcm_sha512:
        case x25519_epid2_aes256gcm_blake2b:
        case x25519_epid2_null_sha512:
        case x25519_epid2_null_blake2b:
                byte[320];
} DAAGroupKey;
~~~

~~~
select(dh_algorithm) {
        case x25519_epid2_chacha20poly1305_sha512:
        case x25519_epid2_chacha20poly1305_blake2b:
        case x25519_epid2_aes256gcm_sha512:
        case x25519_epid2_aes256gcm_blake2b:
        case x25519_epid2_null_sha512:
        case x25519_epid2_null_blake2b:
                byte[128];
} DAASignature;
~~~

### Server Certificates

~~~
enum : uint8 {
        one(1)
} ServerCertificateVersion;
~~~

~~~
byte Date[8];   /* YYYYMMDD according to UTC */
~~~

~~~
struct {
        ServerCertificateVersion version;
        ServerSignatureType algorithm;
        Date expiry;
        ClientID id;
        ServerSignature signature;
        ServerIntermediateCertificate signers_certificate;
        ServerSignature signers_signature;
} ServerCertificate;
~~~

~~~
struct {
        ServerSignatureVersion version;
        ServerSignatureType algorithm;
        Date expiry;
        select(algorithm) {
                case ServerSignatureType.Ed25519:
                        byte[32];
        } public_key;
        byte root_id[32];       /* ServerRootCertificate to use */
        select(root_certificate.algorithm) {
                case ServerSignatureType.Ed25519:
                        byte[64];
        } root_signature;
} ServerIntermediateCertificate;
~~~

~~~
struct {
        ServerSignatureVersion version;
        ServerSignatureType algorithm;
        Date expiry;
        select(algorithm) {
                case ServerSignatureType.Ed25519:
                        byte[32];
        } public_key;
        byte id[32];
} ServerRootCertificate;
~~~

## Record Layer

~~~
byte SessionID[16];
~~~

~~~
uint32 SequenceNumber;
~~~

~~~
uint16 MsgLength;
~~~

~~~
enum : uint8 {
        queue_protocol(1),
        ipv6(2)
} EncapsulatedPayloadType;
~~~

