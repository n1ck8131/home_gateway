# ADR-0006: State, secrets and backup

Status: Accepted

## Context

Operational state needs transactional updates while secret material requires stricter storage, logging and backup boundaries.

## Decision

State uses an embedded transactional store; secret bytes are separate. Unattended backups use age recipient wrapping and portable recovery material.

## Consequences

State schemas and secret storage evolve independently. Backups must carry enough portable metadata for recovery without exposing plaintext secret bytes.

## Verification

Secret redaction and clean restore are required.
