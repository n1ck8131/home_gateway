# ADR-0009: Supply chain and signing

Status: Accepted

## Context

Router, Windows and server artifacts must be reproducible from immutable inputs and independently verifiable before installation.

## Decision

Production inputs are pinned, checksummed and provenance-recorded. Development and release signing keys are separate.

## Consequences

Mutable download references are not production inputs. Development signatures cannot be promoted as release signatures.

## Verification

CI rejects latest, bad SHA and secrets; P12 creates signatures and SBOM.
