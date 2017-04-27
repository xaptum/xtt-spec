---
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
        ins: D.R. Bild
        name: David R. Bild
        organization: Xaptum, Inc.
        email: david.bild@xaptum.com

normative:
  RFC5869:
  RFC7539:
  RFC7693:
  
  SHS:
       title: Secure Hash Standard
       date: 2012-03
       author:
         org: National Institute of Standards and Technology
       seriesinfo:
         NIST: FIPS PUB 180-4

informative:
  RFC5246:
  RFC6347:

--- abstract

This document specifies version 1.0 of the Xaptum Trusted Transit
(XTT) protocol for securing the Internet of Things (IoT). It provides
scalable identitiy provisioning, device authentication, and data
integrity and confidentiality.

--- middle

# Introduction

DISCLAIMER: This is a WIP draft and has not yet seen significant
security analysis.

[TODO] (1 par.) Describe primary goals of XTT

- Identity Provisioning: [TODO] (1 par.) describe desired provisioning
  properites

- Authenticiation: [TODO] (1 par.) describe desired authentication
  properties

- Integrity: [TODO] (1 par.) describe desired integrity properties

- Confidentiality: [TODO] (1 par.) describe desired confidentiality
  properties

[TODO] (1 par.) Describe attack/threat model. What view/control does
the attacker have, e.g., RFC3552.

XTT consists of three primary components:

- An identity provisioning protocol ({{identity-provisioning-protocol}) that [TODO] (1 par.) describe this protocol

- A session establishment protocol ({{session-establishment-protocol}}) that [TODO] (1 par.) describe this protocol

- A record protocol ({{record-protocol}}) that [TODO] (1 par.) describe this protocol

# Identity Provisioning Protocol

TODO


# Session Establishment Protocol

TODO


# Record Protocol

TODO

