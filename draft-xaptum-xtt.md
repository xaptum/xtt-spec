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
  RFC7296:

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

  SIGMA:
       title: "SIGMA: the 'SIGn-and-MAc' approach to authenticated Diffie-Hellman and its use in the IKE protocols"
       date:  2003-06
       author: 
       -
         ins: H. Krawczyk
         name: Hugo Krawczyk
       seriesinfo: Proceedings of CRYPTO 2003

  SIGMASEC:
       title: "Security Analysis of IKE's Signature-Based Key-Exchange Protocol"
       date: 2002-10
       author:
       -
         ins: R. Canetti
         name: Ran Canetti
       -
         ins: H. Krawczyk
         name: Hugo Krawczyk

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
* Heavyweight (heavy use of bandwidth during handshake)
* Designed around one-way, not mutual, authentication
* Non-confidential communication of identities during handshake
* Security session tied to connectivity session
    * Having to re-run handshake every time underlying connection/IP changes compounds bandwidth problem

(TODO) (1 list) what (D)TLS doesn't offer that IoT requires

### Differences from QUIC
* Security session tied to connectivity session
* Not designed for mutual authentication

(TODO) (1 list) what QUIC doesn't offer that IoT requires

### Differences from IKE/IPSec
* Pushing data requires performing full Two-Round-Trip handshake first
* Protects identity of server, not client, which is the opposite of what's needed in IoT
* Very complex to configure, and easy to get wrong

(TODO) (1 list) what IKE doesn't offer that IoT requires

### Differences from Double-Ratchet-based Protocols
* Per-message key updating is too heavy for most IoT, which doesn't require per-message forward secrecy
* Doesn't address identification (uses trust on first use)

(TODO) (1 list) what Double-Ratchet doesn't offer that IoT requires

### Differences from Noise
* Designed mainly for either pre-shared (or statically-known) keys, or for unauthenticated communication

(TODO) (1 list) what Noise doesn't offer that IoT requires

### Differences from MinimaLT
* Requires a highly-available directory service for name-lookup (unnecessary in IoT)
* Reliable-transport only (can cause issues on lossy networks commonly encountered in IoT)
* User-level authentication is inappropriate for IoT (devices aren't multi-user)

(TODO) (1 list) what MinimalLT doesn't offer that IoT requires

# Protocol Overview

An XTT session is started using one of two related but distinct
handshake protocols: one to create an Authenticated Session,
and another to both create an Authenticated Session
and provision a ClientID to the client.
Running an Authenticated Session handshake requires
that a ClientID handshake has successfully been
performed at least once previously.

The ClientID handshake is used to authenticate both parties
as being members of recognized and permissioned groups.
The typical case is of a client proving membership in a group
permissioned to access a private network, and a server
proving membership in the group of access points for that network.
Upon successful completion of a ClientID handshake,
the server provisions to the client a ClientID, a unique
identifier within the client's group.
In addition, the client and server have now negotiated
shared secret material that can be used for future authentication,
without requiring the public-cryptography-based authentication
of the ClientID handshake.

Note that the lifetime of a given ClientID, i.e. the time between
successive ClientID handshakes, is up to the discretion of the client.
It is possible for a given physical endpoint to perform a ClientID handshake
only once (due to, for example, hardware constraints the preclude the required signatures)
and retain the same ClientID for its entire lifetime.
Conversely, a client that does not wish its messages to be linkable
by passive attackers
may perform a ClientID handshake as often as every message;
in fact, by using anonymized signature algorithms (e.g. Direct Anonymous Attestation),
a client may keep active attackers and even the server from being
able to link its messages to one another.

The XTT AuthenticatedSession handshake can be performed after
(or at the same time as) a successful ClientID handshake.
The AuthenticatedSession handshake leverages existing
secret material shared between the client and server
to generate shared secret cryptographic keys,
to be used for encrypting and authenticating subsequent messages.

Both XTT handshake protocols are based on the
SigMA family of authenticated key exchange protocols,
which is also the basis for signature-based authentication
in the Internet Key Exchange version 2 (IKEv2) protocol {{RFC7296}}
used in the IPSec protocol suite.
Specifically, the XTT protocol uses
the SigMA-I variant described in {{SIGMA}}.
In particular, note that the present protocol does not place
the MAC under the signature, as is done in IKEv2
(this is referred to as variant (ii) in {{SIGMA}}).
A formal security analysis of the SigMA protocols can be found in {{SIGMASEC}}.

The handshake protocols are authenticated Diffie-Hellman key exchanges.
Both protocols require three messages,
and only one full round-trip (1 RTT) before a client can begin pushing traffic.
The client, who is always the initiator of a handshake,
may choose to begin pushing traffic with the third message,
before receiving the final response from the server.
The reason for requiring 1 RTT
(in distinction to the 0-RTT option proposed for the upcoming TLSv1.3 standard)
is to protect against replay attacks.
The handshake protocol protects the confidentiality of the
client's identity from both passive and active attackers,
while protecting the server's identity from passive attackers
(this isn't an issue in IoT, as the server's identity is usually known).

(TODO) Specific handshake design aspects
* Small, fixed-size messages during handshake
    * No arbitrary-length certificate chains

~~~
        Client                                             Server
        -----------------------             -----------------------
  
         CLIENTINIT
         + version
         + crypto-spec
         + session_id_seed_c
         + signing nonce
         + ECDHE public key      ------->
                                           
                                             SERVERINITANDATTEST ^ < Hk
                                                       version + | 
                                                   crypto-spec + | 
                                             session_id_seed_c + |
                                              ECDHE public key + | 
                                                 {certificate} + | 
                                           {session_id_seed_s} + | 
                                                   {signature} + |
                                 <-------      {server cookie} + v 

  Hk > ^ CLIENTATTEST 
       | + {DAA group key}
       | + ({identity request})
       v + {DAA signature}
  Sk > ^
       | + ([Application Data])  ------->
       v

                                                                 ^ < Sk
                                                (SERVERFINISHED) |
                                 <------- ([identity confirm]) + |
                                                                 v
  
  Sk > ^                                                         ^ < Sk
       |  RECORDREGULAR                            RECORDREGULAR |
       |  + [Application Data]   <------>   [Application Data] + |
       v                                                         v
  
              +  Indicates message subfields

              () Indicates optional messages/subfields

              {} Indicates data encrypted using handshake keys
  
              [] Indicates data encrypted using session keys
  
         Hk > ^ 
              | Indicates data MAC'd using handshake keys
              v  
  
         Sk > ^ 
              | Indicates data MAC'd using session keys
              v  
~~~
{: #xtt-provisioning title="Message flow for XTT Identity Provisioning Handshake"}

~~~
      Client                                                Server
     ^ ClientInit
     | + version and crypto-spec
     | + ECDHE public key
     v + session id seed          -------> 
                                            
                                              ServerInitAndAttest ^    
                                        version and crypto-spec + |
                                               ECDHE public key + |     
                                                  {certificate} + |     
                                              {session id seed} + |     
                                                    {signature} + v
                                  <-------
     ^  ClientAttest 
     | + {identity}
     | + {psk signature}
     v * [Application Data]       ------->
                                  <------        ServerFinished *

       [Application Data]         <------>     [Application Data]

            +  Indicates message subfields
              
            *  Indicates optional subfields/messages
              
            {} Indicates messages protected using
               handshake keys
               
            [] Indicates messages protected using
               session keys
~~~
{: #xtt-session title="Message flow for XTT Session Creation Handshake"}

(TODO) record layer

# Handshake Protocols

## Features Common to All Handshakes
The first two messages of a handshake (ClientInit and ServerInitAndAttest)
are the same for both handshake types (ClientID and AuthenticatedSession).
When responding to a ClientInit with a ServerInitAndAttest,
an implementation MAY store all necessary state in the ServerCookie
embedded in the ServerInitAndAttest and save no state locally.

After receiving a ServerInitAndAttest,
a client responds with a ClientAttest message.
There are four variants of ClientAttest message,
where two are for a ClientID handshake and two
are for an AuthenticatedSession handshake.
For each handshake type, the two variants indicate whether
or not a payload is included with the message.

### ClientInit Message
All handshakes begin with the client sending a ClientInit message to the server.
A client may resend a ClientInit if it has not received a ServerInitAndAttest
in response within a timeout period.
There is no requirement that ClientInit retries be identical, as long
as a client only responds to one ServerInitAndAttest response.

Structure of this message:

~~~
struct {
    MsgType type = client_init;
    Version version;
    SuiteSpec spec;
    SessionIDSeed session_id_seed;
    SigningNonce client_nonce;
    DHKeyShare client_dh_keyshare;
} ClientInit;
~~~

### ServerInitAndAttest

Structure of this message:

~~~
aead_struct<handshake_keys>(
    MsgType type = server_init_and_attest;
    Version version;
    SuiteSpec spec;
    SessionIDSeed session_id_seed;   /* echo from client */
    DHKeyShare server_dh_keyshare;
)[
    ServerCertificate certificate;
    SessionIDSeed session_id_seed;
    ServerSignature server_signature;
    ServerCookie server_cookie;
] ServerInitAndAttest;
~~~

## Identity Provisioning Protocol
This handshake provisions a ClientID to a client
and simultaneously creates an AuthenticatedSession.

### ClientIdentity_ClientAttest

~~~
aead_struct<handshake_keys>(
    MsgType type =  MsgType.id_clientattest_nopayload;
    Version version;
    SuiteSpec spec;
    byte flags[1];
    ServerCookie server_cookie;     /* echo from server */
}[
    DAAGroupKey daa_gpk;
    ClientID id;
    DAASignature signature;
] ClientIdentity_ClientAttest_NoPayload;
~~~

~~~
struct {
    aead_struct<handshake_keys>(
        MsgType type = MsgType.id_clientattest_payload;
        Version version;
        SuiteSpec spec;
        byte flags[1];
        ServerCookie server_cookie;     /* echo from server */
    }[
        DAAGroupKey daa_gpk;
        ClientID id;
        DAASignature signature;
    ];
    aead_struct<session_keys>(
        MsgLength length;               /* total length */
    )[
        EncapsulatedPayloadType payload_type;
        byte payload[length - sizeof(rest_of_message)];
    ];
} ClientIdentity_ClientAttest_Payload;
~~~

~~~
aead_struct<session_keys>(
    MsgType type = MsgType.id_serverfinished;
    Version version;
    SuiteSpec spec;
)[
    ClientID client_id;     /* confirm id of client */
    FinishedContext ctx;
];
~~~


## Session Establishment Protocol

### Session_ClientAttest

~~~
aead_struct<handshake_keys>(
    MsgType type =  MsgType.session_clientattest_nopayload;
    Version version;
    SuiteSpec spec;
    byte flags[1];
    ServerCookie server_cookie;     /* echo from server */
}[
    DAAGroupKey daa_gpk;
    ClientID id;
    DAASignature signature;
] MsgType.session_ClientAttest_NoPayload;
~~~

~~~
struct {
    aead_struct<handshake_keys>(
        MsgType type = MsgType.session_clientattest_payload;
        Version version;
        SuiteSpec spec;
        byte flags[1];
        ServerCookie server_cookie;     /* echo from server */
    }[
        DAAGroupKey daa_gpk;
        ClientID id;
        DAASignature signature;
    ];
    aead_struct<session_keys>(
        MsgLength length;               /* total length */
    )[
        EncapsulatedPayloadType payload_type;
        byte payload[length - sizeof(rest_of_message)];
    ];
} MsgType.session_ClientAttest_Payload;
~~~

~~~
aead_struct<session_keys>(
    MsgType type = MsgType.session_serverfinished;
    Version version;
    SuiteSpec spec;
)[
    FinishedContext ctx;
];
~~~

# Record Protocol

~~~
aead_struct<session_keys>(
    MsgType type = MsgType.record_regular;
    Version version;
    SessionID session_id;
    SequenceNumber seq_num;
    MsgLength length;
)[
    EncapsulatedPayloadType payload_type;
    byte payload[length - sizeof(rest_of_message)];
];
~~~

# Error Handling

(TODO)

# Cryptographic Computations

## Notation

## Handshake Contexts

## Key Calculation and Schedule

## SessionID Generation

## ECDHE Parameters
The size and interpretation of a value of type DHKeyShare
depends on the Diffie-Hellman algorithm specified in the handshake messages.

Currently, only x25519 is supported by the protocol.

For x25519, the contents are the byte string inputs and
outputs of the corresponding functions defined in {{RFC7748}}.
The size of the DHKeyShare in this case is 32 bytes.

## Signature Algorithms

## Per-message Nonce Calculation

(TODO)

--- back

# State Machine

This section provides a summary of the legal state machine transitions
for the client and server handshakes.  State names (in all capitals,
e.g., START) have no formal meaning, but are provided for ease of
comprehension. Messages which are sent only sometimes are indicated in
`[]`.
(TODO)

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

Optional components are denoted by enclosing them in `[[ ]]` double
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
    id_clientattest_response_nopayload_ip(0x11),
    id_clientattest_response_payload_ip(0x12),
    id_clientattest_response_nopayload_noip(0x13),
    id_clientattest_response_payload_noip(0x14),
    id_clientattest_noresponse_payload_ip(0x15),
    id_clientattest_noresponse_payload_noip(0x16),
    id_serverfinished(0x17),
    session_clientattest_response_nopayload_ip(0x21),
    session_clientattest_response_payload_ip(0x22),
    session_clientattest_response_nopayload_noip(0x23),
    session_clientattest_response_payload_noip(0x24),
    session_clientattest_noresponse_payload_ip(0x25),
    session_clientattest_noresponse_payload_noip(0x26),
    session_serverfinished(0x27),
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
    byte[<size of public key for this algorithm>];
} DHKeyShare;
~~~

~~~
enum : uint8 {
    Ed25519(1)
} ServerSignatureType;
~~~

~~~
select(server_signature_algorithm) {
    byte[<size of signature for this algorithm>];
} ServerSignature;
~~~

~~~
select(server_signature_algorithm) {
    byte[<size of public key for this algorithm>];
} ServerSignaturePublicKey;
~~~

### DAA Types

~~~
select(dh_algorithm) {
    byte[<size of group public key for this algorithm>];
} DAAGroupKey;
~~~

~~~
select(dh_algorithm) {
    byte[<size of signature for this algorithm>];
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
    ServerSignaturePublicKey public_key;
    byte root_id[32];       /* ServerRootCertificate to use */
    ServerSignature root_signature;
} ServerIntermediateCertificate;
~~~

~~~
struct {
    ServerSignatureVersion version;
    ServerSignatureType algorithm;
    Date expiry;
    ServerSignaturePublicKey public_key;
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

