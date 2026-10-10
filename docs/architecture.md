# Architecture

The project is deliberately split into four replaceable layers:

1. **Model**: an instruction-tuned open-weight model plus a LoRA adapter. It reasons over the supplied question and context; it does not become a database of current security facts.
2. **Knowledge base**: versioned source documents indexed in local SQLite FTS. Raw documents and reviewed guidance are separately labelled. Retrieval supplies citations but cannot override the system prompt.
3. **Assessment logic**: prompt construction, evidence hashing, structured response requests, context persistence, and scope checks. This layer does not execute commands.
4. **Tool gateway (future)**: a separate, approval-gated process. It must enforce explicit target allowlists, rate limits, command previews, audit logs, and human approval. Model text is never executable authority.

## What belongs where

| Capability | Fine-tune | Knowledge base | External tool / human |
|---|---|---|---|
| Evidence-first reporting style | Yes | No | No |
| Current vendor syntax and CVEs | No | Yes | Verify |
| Interpret supplied HTTP/AD tool output | Yes | Supporting references | No invented output |
| Live enumeration or validation | No | No | Scope-gated tools and human approval |
| Confirm a vulnerability | No | Supporting criteria | Evidence and assessor judgement |

## Base-model decision

Default to `Qwen/Qwen2.5-7B-Instruct` for the first measured adapter. It has 7.61B parameters, an Apache-2.0 licence, and a 131k-token context window; it is a meaningful quality increase from the current 3B model while still practical in 4-bit form on one 16 GB T4 for conservative QLoRA runs. Keep the 3B adapter as the fast, lower-memory baseline. Evaluate `Qwen/Qwen3-8B` later, not by assumption: it uses a newer architecture and has a 40,960-token configured context, but it needs a compatible current Transformers/TRL stack and a fresh baseline evaluation.

For local inference, use a 4-bit GGUF/GPTQ/AWQ runtime or Transformers + bitsandbytes; an 8B 4-bit model generally needs roughly 5--7 GB for weights plus KV-cache and runtime overhead. Model quality for security work must be established by the local benchmark, not generic model scores.

| Candidate | Role in this project | Local 4-bit profile | Fine-tuning profile | Decision rule |
|---|---|---|---|---|
| Qwen 2.5 3B Instruct | Fast control baseline and laptop-friendly assistant | ~3--5 GB practical runtime budget | Comfortable on one T4 | Retain as the speed baseline; do not assume it is the quality winner. |
| Qwen 2.5 7B Instruct | Default first specialist adapter | ~7--10 GB including useful KV cache/runtime headroom | Conservative QLoRA fits a 16 GB T4; use 2 T4s with Accelerate only after the single-GPU run is stable | First adapter to measure against the 3B baseline. |
| Qwen3 8B | Upgrade candidate | ~8--11 GB practical runtime budget | QLoRA requires the newer model/TRL/chat-template stack | Adopt only if held-out Web and AD scores improve with no safety regression. |

Avoid models marketed as security-specialized unless their provenance, licence, data handling, and benchmark performance are independently reviewed. Domain capability here comes primarily from curated assessment examples, retrieval, and evidence discipline—not a model name.
