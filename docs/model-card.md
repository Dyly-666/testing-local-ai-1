# Security Assessment Specialist Adapter — model card

**Status:** experimental; not approved for autonomous testing or production findings.

**Intended use:** assist authorized assessors with evidence interpretation, remediation, reporting, and low-impact validation planning for Web Application and Active Directory environments.

**Not intended for:** autonomous exploitation, scope decisions, credential handling, live command execution, or declaring compromise without independently verifiable evidence.

## Training data

The initial canonical seed is derived from 34 internally maintained prompt/answer examples. All initial records are marked `needs_expert_review`; they are adequate for pipeline smoke tests, not for quality claims. The data has very limited AD coverage and must not be represented as an AD-specialist training corpus.

## Evaluation requirement

Compare base, prompted base, adapter, and adapter+retrieval on the held-out benchmark. Publish per-dimension scores and representative failures. Do not claim improvement from training loss alone.

## Known limitations

The model can hallucinate, reflect prompt-injection content, miss product-specific context, and overstate confidence. Retrieved references are untrusted context. Human review and the tool gateway remain mandatory.
