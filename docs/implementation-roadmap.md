# Implementation roadmap

## Phase 0 — complete: establish a safe, measurable baseline

- [x] Remove the exposed local Kaggle credential and ignore future secret files.
- [x] Preserve raw inputs; create a canonical deduplicated corpus with per-record provenance, labels, hashes, and human review states.
- [x] Block production training on unapproved examples.
- [x] Add deterministic QLoRA configuration, validation, checkpointing, resumption, and completion-only labels.
- [x] Add a held-out benchmark, regression scorer, local KB baseline, and assessment-context store.

## Phase 1 — required before a quality claim

1. Expert-review every seed example in `reports/seed_dataset_review.md`; correct inaccurate statements, add source/licence notes, and approve only records that meet the rubric.
2. Add at least 150 held-out, human-scored benchmark cases before choosing a base model. Include Web/AD parity, tool-output interpretation, negative findings, stale evidence, false-positive traps, and adversarial documents.
3. Build a curated corpus with substantial AD coverage. The current two AD records are insufficient; target diverse LDAP, Kerberos, AD CS, ACL, delegation, trust, and BloodHound-evidence interpretation examples with safe evidence requirements.
4. Run and score the four benchmark conditions. Make a go/no-go decision from expert scores, not loss.

## Phase 2 — retrieve and improve

1. Ingest reviewed primary sources and maintain a retrieval relevance set.
2. Measure lexical FTS retrieval; add a local embedding/hybrid index only if it increases citation relevance without introducing stale or unrelated context.
3. Add conversation summaries and assessment artefacts with encryption-at-rest appropriate to your environment.
4. Version data, adapters, benchmark outputs, and KB snapshots together in release manifests.

## Phase 3 — optional tool gateway

Only after the assistant is reliable at analysis and reporting, add a separate tool gateway. It must independently validate scope, canonicalize and allowlist targets, enforce rate and concurrency limits, preview commands, require human approval for intrusive work, scrub logs, and preserve immutable audit events. Model output must never be sent directly to a shell, scanner, or network client.
