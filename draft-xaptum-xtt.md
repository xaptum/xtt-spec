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

# Protocol Data Structures and Constant Values

This section describes protocol types and constants.

(TODO)

