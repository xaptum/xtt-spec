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
  RFC2104:
  RFC5116:
  RFC5869:
  RFC7539:
  RFC7693:
  RFC7748:
  RFC8032:
  
  SHS:
       title: Secure Hash Standard
       date: 2012-03
       author:
         org: National Institute of Standards and Technology
       seriesinfo:
         NIST: FIPS PUB 180-4

informative:
  RFC2119:
  RFC3552:
  RFC5246:
  RFC6347:
  RFC7296:

  DAA:
       title: "Direct Anonymous Attestation"
       date: 2004-02-11
       author:
       -
         ins: E. Brickell
         name: Ernie Brickell
       -
         ins: J. Camenisch
         name: Jan Camenisch
       -
         ins: L. Chen
         name: Liqun Chen

       seriesinfo: Proceedings of the 11th ACM conference on Computer and communications security

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

The primary goal of the XTT protocol is to provide a secure communication
channel between an Internet of Things (IoT) device in the field and a backend
network or server. The nature of the IoT imposes several constraints that
differ from traditional transport layer security:

- Identity Provisioning: IoT devices will be numerous and must be low-cost, so
  manual provisioning of preshared keys (PSKs) or client certificates will not
  scale. Instead, devices must be provisioned long-term cryptographic
  identities in the field on first use. XTT leverages the Direct Anonymous
  Attestation {{DAA}} capabilties of modern processors to enable this.

- IP Address Mobility: The last-mile Internet access can change frequently for
  IoT devices. Needing to reestablish the secure channel after every IP
  address change consumes precious energy and bandwidth.  XTT decouples the
  secure channel from the underlying TCP/IP or UDP/IP transport socket

- DoS Resistance: The secure communication channel is established over the
  public Internet, so the protocol must be designed to help the server-side
  resist denial of service (DoS) attacks.

The protocol must also provide the following traditional security properties:

- Mutual Authentication: Both the client and server sides are always
  authenticated. Server authentication happens via ECDSA and client
  authentication happens via symmetric-key-signature or DAA.

- Integrity: Data sent over the channel cannot be modified by an attacker.

- Confidentiality: Data sent over the channel is visible only to the
  endpoints. This property is optional; encryption may be disabled if the
  channel is tunneling data that was already encrypted.

The protocol must resist an attacker with complete control of the network, as
described in {{RFC3552}}.

XTT consists of three primary components:

- An identity provisioning protocol ({{identity-provisioning-protocol}}) used
  by the device to request an identity from the server and establish a
  long-term shared secret. 

- A session establishment protocol ({{session-establishment-protocol}}) that
  (TODO) (1 par.) describe this protocol

- A record protocol ({{record-protocol}}) that (TODO) (1 par.)  describe this
  protocol

## Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in RFC
2119 {{RFC2119}}.

The following terms are used:

client: The initiator in a handshake.

connection: A transport-layer connection between client and server, over which XTT traffic is sent.

endpoint: The physical device that is acting as either client or server during communication.

handshake: An initial negotiation between client and server for either provisioning
authorization data to the client or establishing shared cryptographic information
for subsequent communication.

identity: A universally-unique tag used to identify a client to a server or to any other clients
that may be peers.

server: The responder in a handshake.

session: A collection of cryptographic parameters and secrets used for secure communication.

## Use Cases

(TODO)


## Design Goals

(TODO)

* Small, fixed-size messages during handshake
    * No arbitrary-length certificate chains

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
The XTT protocol provisions shared, secret state between a client
and a server that may persist past the lifetime of the underlying connection.
This shared state is grouped into two classes:

* A long-term identity
  for a client and the shared secrets used to prove that identity
  to the server during future communication
* A session consisting of cryptographic material to be used
  for message authentication and confidentiality

A client requests an identity from a server using the handshake shown
in ({{xtt-provisioning}}) and described in ({{identity-provisioning-protocol}}).
To complete the handshake, the client must prove its membership in
a client group recognized by the server, using a Direct Anonymous Attestation (DAA) signature.

~~~
        Client                                             Server
        -----------------------             -----------------------
         CLIENTINIT
         + length
         + version
         + suite_spec
         + nonce_c 
         + dh_keyshare_c         ------->
                                             SERVERINITANDATTEST ^ < Hk
                                                        length + |
                                                       version + | 
                                                    suite_spec + | 
                                                 dh_keyshare_s + | 
                                                 {certificate} + | 
                                                 {signature_s} + |
                                 <-------      {server_cookie} + v 
  Hk > ^ IDENTITY_CLIENTATTEST 
       | + length
       | + version
       | + suite_spec
       | + server_cookie
       | + {daa_gpk}
       | + {id_c}
       v + {daa_signature_c}     ------->
                                         IDENTITY_SERVERFINISHED ^ < Hk
                                                        length + |
                                                       version + |
                                                    suite_spec + |
                                                        {id_c} + |
                                 <-------    {awareness_proof} + v
  
              +    Indicates message subfields
              ()   Indicates optional messages/subfields
              {}   Indicates data encrypted using handshake keys
              Hk > Indicates data MAC'd using handshake keys
~~~
{: #xtt-provisioning title="Message flow for XTT Identity Provisioning Handshake"}

Once a client possesses an identity,
it authenticates that identity to a server and negotiates a session,
using the handshake shown
in ({{xtt-session}}) and described in ({{session-establishment-protocol}}).
The cryptographic parameters and materials negotiated during the session-establishment
handshake allow the client and server to protect (check authentication and integrity,
and optionally encrypt) application layer traffic using a record-level protocol
also shown in ({{xtt-session}}) and described
in ({{record-protocol}}).

~~~
        Client                                             Server
        -----------------------             -----------------------
         CLIENTINIT
         + length
         + version
         + suite_spec
         + nonce_c 
         + dh_keyshare_c         ------->
                                             SERVERINITANDATTEST ^ < Hk
                                                        length + |
                                                       version + | 
                                                    suite_spec + | 
                                                 dh_keyshare_s + | 
                                                 {certificate} + | 
                                                 {signature_s} + |
                                 <-------      {server_cookie} + v 
  Hk > ^ SESSION_CLIENTATTEST 
       | + length
       | + version
       | + suite_spec
       | + server_cookie
       | + {session_id}
       | + {id_c}
       v + {signature_c}
  Sk > ^ (RECORDREGULAR)
       | + (length)
       | + (version)
       | + (session_id)
       | + (seq_num)
       | + ([payload_type])
       v + ([payload])           ------->
                                          SESSION_SERVERFINISHED ^ < Sk
                                                        length + |
                                                       version + |
                                                    suite_spec + |
                                                  {session_id} + |
                                 <-------    {awareness_proof} + v

  Sk > ^ RECORDREGULAR                             RECORDREGULAR ^ < Sk
       | + length                                       length + |
       | + version                                     version + |
       | + session_id                               session_id + |
       | + seq_num                                     seq_num + |
       | + [payload_type]                       [payload_type] + |
       v + [payload]             <------>            [payload] + v
  
              +    Indicates message subfields
              ()   Indicates optional messages/subfields
              {}   Indicates data encrypted using handshake keys
              []   Indicates data encrypted using session keys
              Hk > Indicates data MAC'd using handshake keys
              Sk > Indicates data MAC'd using session keys
~~~
{: #xtt-session title="Message flow for XTT Session Creation Handshake and Record-Level Protocol"}

# Handshake Protocols
The XTT protocol includes two handshake protocols:
an identity-provisioning protocol,
and a session-establishment protocol.

The messages defined below are given to the underlying transport-layer
as-is (i.e. there is no further framing).
A handshake MUST be completed within a single
underlying connection with the same physical endpoint.

## Common Messages
Both handshake protocols begin with the same two messages:
the ClientInit and the ServerInitAndAttest.

### ClientInit
A client initiates a handshake
with a ClientInit message.
This message determines the parameters
(version and cryptographic algorithms)
of the subsequent handshake,
provides a nonce for the server to sign
(to prevent replay attacks of this handshake),
and communicates the client's ephemeral Diffie-Hellman public key.

Structure of this message:

~~~
struct {
    MsgType type = client_init;
    MsgLength length;
    Version version;
    SuiteSpec suite_spec;
    SigningNonce nonce_c;
    DHKeyShare dh_keyshare_c;
} ClientInit;
~~~

### ServerInitAndAttest
Upon receiving a ClientInit message, and assuming the version
and suite_spec are acceptable, a server responds with a
ServerInitAndAttest message.
This message confirms the version and suite_spec,
communicates the server's ephemeral Diffie-Hellman public key,
authenticates the server's identity,
and provides the client with a ServerCookie.
This ServerCookie is used to prevent replay attacks against
the server, and to challenge the client's return-routability.

The ServerCookie also allows a server implementation
to refrain from storing any local state until the client
proves return-routability; see ({{server-cookie-and-dos-attacks}}).

The message is AEAD-protected (using the algorithm specified in the suite_spec)
using the `server_handshake_send_key` and `server_handshake_send_iv`.
The `signature_s` and `certificate` are created as described in ({{serversignature}}).

Structure of this message:

~~~
aead_struct<server_handshake_send_keys>(
    MsgType type = server_init_and_attest;
    MsgLength length;
    Version version;
    SuiteSpec suite_spec;
    DHKeyShare dh_keyshare_s;
)[
    ServerCertificate certificate;
    ServerSignature signature_s;
    ServerCookie server_cookie;
] ServerInitAndAttest;
~~~

## Identity Provisioning Protocol
This handshake provisions an identity to a client,
along with the shared secrets necessary for the client
to prove possesion of the identity.
A successful identity-provisioning handshake is required
before a client may perform a session-establishment handshake.

### ClientIdentity_ClientAttest
Once a client receives a ServerInitAndAttest message during an identity-provisioning handshake,
and assuming the ServerInitAndAttest is correctly
validated (MAC and signature are verified, and version and suite_spec
correspond to those sent in the ClientInit message),
the client responds with a ClientIdentity_ClientAttest message.
This message echoes the ServerCookie (to prove return-reachability),
authenticates the client's membership in an authorized group,
and requests to be provisioned an identity.

A client may indicate a specific ClientID in the `id_c` field of a ClientIdentity_ClientAttest
message, in order to request that specific ClientID be provisioned to it.
Otherwise, if the client wishes the server to select the ClientID for it,
the `id_c` field MUST be set to all zeroes.

The message is AEAD-protected (using the algorithm specified in the suite_spec)
using the `client_handshake_send_key` and `client_handshake_send_iv`.
The `daa_signature_c` is created as described in ({{daasignature}}).

Structure of this message:

~~~
aead_struct<client_handshake_send_keys>(
    MsgType type =  MsgType.id_clientattest;
    MsgLength length;
    Version version;
    SuiteSpec suite_spec;
    ServerCookie server_cookie;     /* echo from server */
}[
    DAAGroupKey daa_gpk;
    ClientID id_c;                  /* all zeroes if not specific id */
    DAASignature daa_signature_c;
] ClientIdentity_ClientAttest;
~~~

### ClientIdentity_ServerFinished
Once a server receives a ClientIdentity_ClientAttest message,
and if that message is validated
(message authentication code and client signature verified,
and version and suite_spec are acceptable),
the server responds with a ClientIdentity_ServerFinished message.

The ClientIdentity_ServerFinished message informs the client of the
ClientID that has been provisioned to it
(either echoing the same `id_c` requested in the ClientAttest
message or sending the newly-provisioned id if `id_c` was all zeroes).
In addition, the ServerFinished message contains
a hash of the successful handshake, authenticated
using a key derived from the LongtermSecret that has been provisioned.
This is to provide 'peer-awareness' to the client, so the client
and server can confirm they have the same view of the provisioned
ClientID and LongtermSecret.

The message is AEAD-protected (using the algorithm specified in the suite_spec)
using the `server_handshake_send_key` and `server_handshake_send_iv`.
The `awareness_proof` is given by `identity_awareness_proof`,
as described in ({{xtt-psk-schedule}}).

Structure of this message:

~~~
aead_struct<server_handshake_send_keys>(
    MsgType type = MsgType.id_serverfinished;
    MsgLength length;
    Version version;
    SuiteSpec suite_spec;
)[
    ClientID id_c;     /* confirm id of client */
    AwarenessProof awareness_proof;
] ClientIdentity_ServerFinished;
~~~

## Session Establishment Protocol
This handshake negotiates a session (cryptographic secrets
used for secure communication), and
requires that a ClientID has been provisioned for this client
via a previous identity-provisioning handshake.
A successful session-establishment handshake is required
before a client may securely communicate via the record-layer protocol.

### Session_ClientAttest
Once a client receives a ServerInitAndAttest message during a session-establishment handshake,
and assuming the ServerInitAndAttest is correctly
validated (MAC and signature are verified, and version and suite_spec
correspond to those sent in the ClientInit message),
the client responds with a Session_ClientAttest message.
This message echoes the ServerCookie (to prove return-reachability),
proves the client's ownership of the claimed ClientID,
and requests to be provisioned a SessionID.

A client may indicate a specific SessionID in the `session_id` field of a ClientAttest
message, in order to request that specific SessionID be provisioned to it.
Otherwise, if the client wishes the server to select the SessionID for it,
the `session_id` field MUST be set to all zeroes.

The message is AEAD-protected (using the algorithm specified in the suite_spec)
using the `client_handshake_send_key` and `client_handshake_send_iv`.
The `signature_c` is created as described in ({{symmetricsignature}}).

Structure of this message:

~~~
aead_struct<client_handshake_send_keys>(
    MsgType type =  MsgType.session_clientattest;
    MsgLength length;
    Version version;
    SuiteSpec spec;
    ServerCookie server_cookie;     /* echo from server */
}[
    SessionID session_id;           /* all zeroes if not specific id */
    ClientID id_c;                  /* from previous identity handshake */
    SymmetricSignature signature_c;
] Session_ClientAttest;
~~~

### Session_ServerFinished
Once a server receives a Session_ClientAttest message,
and if that message is validated
(message authentication code and client signature verified,
and version and suite_spec are acceptable),
the server responds with a Session_ServerFinished message.

The Session_ServerFinished message informs the client of the
SessionID that has been provisioned to it
(either echoing the same `session_id` requested in the Session_ClientAttest
message or sending the newly-provisioned SessionID if `session_id` was all zeroes).
In addition, the ServerFinished message contains
a hash of the successful handshake, authenticated
using a key derived from the cryptographic secrets that have been provisioned.
This is to provide 'peer-awareness' to the client, so the client
and server can confirm they have the same view of the provisioned
secrets necessary for secure communication.

The message is AEAD-protected (using the algorithm specified in the suite_spec)
using the `server_handshake_send_key` and `server_handshake_send_iv`.
The `awareness_proof` is given by `session_awareness_proof`,
as described in ({{xtt-session-schedule}}).

Structure of this message:

~~~
aead_struct<session_keys>(
    MsgType type = MsgType.session_serverfinished;
    MsgLength length;
    Version version;
    SuiteSpec spec;
)[
    SessionID session_id;   /* confirm session_id */
    AwarenessProof awareness_proof;
] Session_ServerFinished;
~~~

## Behaviors Common to Both Handshake Protocols
A client may resend a ClientInit if it has not received a ServerInitAndAttest
in response within a timeout period.
There is no requirement that ClientInit retries be identical, as long
as a client only responds to one ServerInitAndAttest response.

When responding to a ClientInit message with a ServerInitAndAttest,
a server MAY store all necessary state in the ServerCookie
embedded in the ServerInitAndAttest and save no state locally.

A server MAY respond to multiple ClientInit messages from the same client
with not-necessarily identical
ServerInitAndAttest messages before a full handshake is completed with that client.
However, if multiple ClientInitAndAttest replies are sent to the same client
during a handshake and the server is storing state locally after responding
(rather than storing state only in the ServerCookie),
the server MUST ensure that response to any one of the ClientInitAndAttest
is valid.

If a client times-out waiting for a ServerFinished
response to its ClientAttest message,
the client MUST resend identical ClientAttest messages during the handshake,
or else abort the handshake.
If multiple non-identical ClientAttest messages are sent during the same handshake,
the client's and the server's view of the shared secret material negotiated
during the handshake will differ, and communication will be impossible.

A client MUST wait until successful receipt of a ServerFinished
message before initiating a session-establishment handshake.

If a server receives a ClientAttest message
from a client from which it has already received
a ClientAttest message during this handshake,
the server MUST ignore the the extra messages.

# Record Protocol
(TODO): Describe record protocol

~~~
aead_struct<session_keys>(
    MsgType type = MsgType.record_regular;
    MsgLength length;
    Version version;
    SessionID session_id;
    SequenceNumber seq_num;
)[
    EncapsulatedPayloadType payload_type;
    byte payload[length - sizeof(rest_of_message)];
] Record_Regular;
~~~

# Error Handling

(TODO)

# Cryptographic Computations

## Notation
The cryptographic computations used in this protocol make use
of a pseudo-random function `prf`, defined as:

~~~
prf<N>(Key, Input) =
    Keyed pseudo-random function (set during handshake),
    keyed by "Key", with "Input" as input, outputting "N" bytes
~~~

The `prf` is implemented by a keyed hash function.
For the case of the SHA512-based suite_spec options,
`prf` is HMAC, as specified in {{RFC2104}}, using SHA-512,
defined in {{SHS}}, as the underlying hash function.
For the case of the BLAKE2b-based suite_spec options,
`prf` is the BLAKE2b keyed-hash function, as defined in {{RFC7693}}.

In addition, a non-keyed hash, denoted `hash`, will be referenced here.
For the SHA512-based suite_spec options, this is just SHA-512.
For the BLAKE2b-based suite_specs, this is Blake2b with
a zero-length key.

The hashes used in the cryptographic computations described below
use a construction denoted `hash_ext`, which appends the input length
to its input before hashing:

~~~
hash_ext(Input) =
    hash(
        struct {
            uint16 length = Input.length;
            byte input[<input.length>] = Input;
        };
    )
~~~

Similarly, `prf_ext` is defined as the `prf` function with
the output length appended to its input:

~~~
prf_ext<N>(Key, Input) =
    prf<N>(Key,
           struct {
               uint16 out_length = N;
               byte input[<input.length>] = Input;
           };
    )
~~~

## Transcript Hashes

The computation of the shared secret materials requires
various hashes of the handshake messages, in order to bind
these secret materials to the specific handshake.
The definitions of these hash values follow below.

When included in a hash, handshake messages are unencrypted.

~~~
ServerSigHash =
    hash_ext(
        ClientInit ||
        ServerInitAndAttest-up-to-signature
    )
~~~

~~~
HandshakeKeyHash =
    hash_ext(
        hash_ext(
            ClientInit ||
            ServerInitAndAttest-up-to-cookie
        ) ||
        server_cookie
    )
~~~

~~~
ClientSigHash =
    hash_ext(
        hash_ext(
            ClientInit ||
            ServerInitAndAttest-up-to-cookie
        ) ||
        server_cookie ||
        ClientAttest-up-to-signature
    )
~~~

~~~
SessionHash =
    hash_ext(
        hash_ext(
            ClientInit ||
            ServerInitAndAttest-up-to-cookie
        ) ||
        server_cookie ||
        ClientAttest
    )
~~~

~~~
ServerFinishedHash =
    hash_ext(
        hash_ext(
            ClientInit ||
            ServerInitAndAttest-up-to-cookie
        ) ||
        server_cookie ||
        ClientAttest ||
        ServerFinished-up-to-ctx
    )
~~~

## Key Calculation and Schedule
Multiple secret materials are derived from the same input key
by including different handshake context into the call to `prf`.
These contexts are defined in {{xtt-context-table}} below,
and their use is shown in {{xtt-handshake-schedule}},
{{xtt-psk-schedule}}, and {{xtt-session-schedule}}.

| Context                       | Definition                                                  |
|:----------------------------- | -----------------------------------------------------------:|
| ClientHandshakeKeyContext     | ( HandshakeKeyHash   \|\| "XTT handshake client key" )      |
| ClientHandshakeIVContext      | ( HandshakeKeyHash   \|\| "XTT handshake client iv" )       |
| ServerHandshakeKeyContext     | ( HandshakeKeyHash   \|\| "XTT handshake server key" )      |
| ServerHandshakeIVContext      | ( HandshakeKeyHash   \|\| "XTT handshake server iv" )       |
| LongtermSharedSecretContext   | ( ServerFinishedHash \|\| "XTT long-term secret" )          |
| IdentityFinishedContext       | ( ServerFinishedHash \|\| "XTT identity awareness" )        |
| LongtermSecretKeyContext      | ( ServerFinishedHash \|\| "XTT long-term secret key" )      |
| ClientSessionKeyContext       | ( SessionHash        \|\| "XTT session client key" )        |
| ClientSessionIVContext        | ( SessionHash        \|\| "XTT session client iv" )         |
| ServerSessionKeyContext       | ( SessionHash        \|\| "XTT session server key" )        |
| ServerSessionIVContext        | ( SessionHash        \|\| "XTT session server iv" )         |
| SessionFinishedContext        | ( SessionHash        \|\| "XTT session awareness" )         |
{: #xtt-context-table title="Context Strings for Secret Material Derivation"}

The prf is drawn as taking the key argument from the left
and outputting downward.
`DH-shared-secret` is the result of running Diffie-Hellman
using the keys exchanged during the handshake,
and `key_size` and `iv_size` are the key- and nonce-sizes
(respectively) for the AEAD algorithm determined by the suite_spec.

~~~
  (nonce_c | server_cookie)
     |      
     |      
     +--> prf<sizeof(LongtermSecret)>(DH-shared-secret)
           |
           +--> prf<key_size>(ClientHandshakeKeyContext)
           |     |
           |     +--> client_handshake_send_key
           |     |
           |     +--> server_handshake_receive_key
           |
           +--> prf<iv_size>(ClientHandshakeIVContext)
           |     |
           |     +--> client_handshake_send_iv
           |     |
           |     +--> server_handshake_receive_iv
           |
           +--> prf<key_size>(ServerHandshakeKeyContext)
           |     |
           |     +--> client_handshake_receive_key
           |     |
           |     +--> server_handshake_send_key
           |
           +--> prf<iv_size>(ServerHandshakeIVContext)
           |     |
           |     +--> client_handshake_receive_iv
           |     |
           |     +--> server_handshake_send_iv
           |
           +--> handshake_secret
~~~
{: #xtt-handshake-schedule title="Key Schedule for Handshake Keys"}

~~~
  handshake_secret
     |      
     |      
     +--> prf<sizeof(LongtermSecret)>(ClientID)
           |
           +--> prf<sizeof(LongtermSecret)>(LongtermSharedSecretContext)
           |     |
           |     +--> longterm_client_shared_secret
           |
           +--> prf<sizeof(AwarenessProof)>(IdentityFinishedContext)
           |     |
           |     +--> identity_awareness_proof
           |
           +--> prf<sizeof(LongtermSignatureKey)>(LongtermSecretKeyContext)
                 |
                 +--> longterm_client_shared_secret_key
~~~
{: #xtt-psk-schedule title="Derivation of Longterm-Shared-Secret"}

~~~
  handshake_secret
     |      
     |      
     +--> prf<sizeof(LongtermSecret)>(longterm_client_shared_secret)
           |
           +--> prf<key_size>(ClientSessionKeyContext)
           |     |
           |     +--> client_session_send_key
           |     |
           |     +--> server_session_receive_key
           |
           +--> prf<iv_size>(ClientSessionIVContext)
           |     |
           |     +--> client_session_send_iv
           |     |
           |     +--> server_session_receive_iv
           |
           +--> prf<key_size>(ServerSessionKeyContext)
           |     |
           |     +--> client_session_receive_key
           |     |
           |     +--> server_session_send_key
           |
           +--> prf<iv_size>(ServerSessionIVContext)
           |     |
           |     +--> client_session_receive_iv
           |     |
           |     +--> server_session_send_iv
           +--> prf<sizeof(AwarenessProof)>(SessionFinishedContext)
                 |
                 +--> session_awareness_proof
~~~
{: #xtt-session-schedule title="Key Schedule for Handshake Keys"}

## ECDHE Parameters
The size and interpretation of a value of type DHKeyShare
depends on the Diffie-Hellman algorithm specified in the handshake messages.

Currently, only x25519 is supported by the protocol.

For x25519, the contents are the byte string inputs and
outputs of the corresponding functions defined in {{RFC7748}}.
The size of the DHKeyShare in this case is 32 bytes.

## DAA Parameters
(TODO)

EPID2, TPM2.0, and FIDO key/signature sizes.

## Signature Algorithms
The size and interpretation of signature types (signatures and public keys)
depends on the signature algorithm.

### ServerSignature
Currently, the only supported algorithm for the
server's signature in a ServerInitAndAttest is
an EdDSA signature (described in {{RFC8032}}) using the X25519 elliptic curve
(this combination is known as Ed25519).

For Ed25519, the contents of ServerSignaturePublicKey are the byte string
output of the key generation described in {{RFC8032}}, where the byte string
format is defined in {{RFC7748}}.
Similarly, the content of ServerSignature are the byte string output
of the signature algorithm of {{RFC8032}} in the format of {{RFC7748}}.

### SymmetricSignature
(TODO)

### DAASignature
(TODO)

## Per-message Nonce Calculation
A per-session pair of key and IV are created for both sending and receiving data,
upon the successful completion of a handshake.
The client and server each get a pair of sending and receiving keys/IVs
(of course, the server’s sending key/IV matches the client’s receiving key/IV, and vice-versa).
The byte-length of the IVs is that of the nonce for the negotiated AEAD algorithm.

A per-message nonce is generated before AEAD encryption
by left-padding the sequence number (in network byte order)
to the length of the nonce/IV,
then XOR’ing the appropriate IV with this padded sequence number.

A server's ServerInitAndAttest message has sequence number 0,
and its ServerFinished message (either ClientIdentity_ServerFinished
or Session_ServerFinished, depending on the type of handshake)
has sequence number 1.
Similarly, a client's ClientAttest message (either ClientIdentity_ClientAttest
or Session_ClientAttest) has sequence number 0.

At the start of a new session (after a successful handshake),
the two sequence numbers (client-to-server and server-to-client) are reset to 0.
The first record-level payload the client sends after
sending its Session_ClientAttest must have sequence number 0.
Similarly, the first record-level payload sent by the server after
sending its Session_ServerFinished must have sequence number 0.

# Security Considerations
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
Both protocols require four messages.
The server, who is always the responder in a handshake,
sends the final message to provide the client "peer awareness"
(proving to the client that the server is alive and agrees
on the results of the handshake).
The client, who is always the initiator of a handshake,
may choose to begin pushing traffic with the third message of a session-establishment handshake,
before receiving the peer awareness response from the server.
The reason for requiring a full roundtrip before application traffic is allowed
(in contrast to the 0-RTT option proposed for the upcoming TLSv1.3 standard)
is to protect against replay attacks.

The handshake protocol protects the confidentiality of the
client's identity from both passive and active attackers,
while protecting the server's identity from passive attackers;
in IoT, client identities are more likely to be sensitive than
server identities.
Assuming at least one side (client or server) produces new
Diffie-Hellman key pairs for each handshake,
the protocol also provides forward secrecy.

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
Comments begin with `/\*` and end with `\*/`.
Concatenation of byte strings is denoted `||`

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
    client_identity_client_init(0x11),
    client_identity_server_init_and_attest(0x12),
    id_clientattest_nopayload(0x13),
    id_clientattest_payload(0x14),
    id_serverfinished(0x15),
    session_client_init(0x21),
    session_server_init_and_attest(0x22),
    session_clientattest_nopayload(0x23),
    session_clientattest_payload(0x24),
    session_serverfinished(0x25),
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
    x25519_epid2_ed25519_chacha20poly1305_sha512(1),
    x25519_epid2_ed25519_chacha20poly1305_blake2b(2),
    x25519_epid2_ed25519_aes256gcm_sha512(3),
    x25519_epid2_ed25519_aes256gcm_blake2b(4),
    x25519_epid2_ed25519_null_sha512(5),
    x25519_epid2_ed25519_null_blake2b(6)
} SuiteSpec;
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
byte AwarenessProof[16];
~~~

~~~
byte DHKeyShare[<size of public key for this algorithm>];
~~~

### Signature Types

~~~
byte SymmetricSignature[<size of prf output>];
~~~

~~~
byte SymmetricSignatureKey[64];
~~~

~~~
byte ServerSignature[<size of signature for this algorithm>];
~~~

~~~
byte ServerSignaturePublicKey[<size of public key for this algorithm>];
~~~

~~~
byte DAAGroupKey[<size of group public key for this algorithm>];
~~~

~~~
byte DAASignature[<size of signature for this algorithm>];
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
    Date expiry;
    ClientID id;
    ServerSignaturePublicKey public_key;
    ServerIntermediateCertificate signers_certificate;
    ServerSignature signers_signature;
} ServerCertificate;
~~~

~~~
struct {
    ServerSignatureVersion version;
    Date expiry;
    ServerSignaturePublicKey public_key;
    byte root_id[32];       /* ServerRootCertificate to use */
    ServerSignature root_signature;
} ServerIntermediateCertificate;
~~~

~~~
struct {
    ServerSignatureVersion version;
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

# Implementation Notes

## Distributed Servers and Proxies
Because the identity and session may be long-lived and are not tied to
the underlying network connection,
the protocol makes no requirement that a client only communicate
with a single physical server endpoint during the lifetime
of an identity or session.
A common use case is of
multiple server endpoints that share long-term storage,
all aware of the state shared with a client endpoint.

Similarly, the protocol makes no requirement that the physical endpoint
that completes the identity-provisioning handshake be the same physical
endpoint to which this identity is given.
For example, a proxy capable of producing DAA signatures may request
multiple distinct identities for the distinct endpoints behind it.

## Server Cookie and DoS Attacks
Server implementation MAY refrain from storing local state after
responding to a ClientInit, and instead store state in the ServerCookie.
Either way, the implementation MUST have a means of authenticating
an ServerCookie echoed back to a server as being generated by that server
and of checking that the ServerCookie has not been seen by that server before.
One possible implementation of this is to AEAD encrypt the cookie with a key
known only to the server and rotated frequently:
upon receiving a cookie, the server checks that the cookie can be decrypted
with a recent key, proving authenticity and freshness,
and remembering that cookie has having been seen (only cookies
generated using the recent key need be remembered), proving uniqueness.


## Underlying Transport Protocol
(TODO)
Notes on fragmenting, ordering, etc.

## Cryptographic Requirements
(TODO)
Requirements for identity-provisioning handshake, for session-establishment handshake,
and for record-level communication.
