# Local Security Assessment Specialist

An evidence-led local assistant for authorized Web Application and Active Directory security assessments. It is a **copilot**, not an autonomous scanner: it never treats model text as permission to execute tools, and it must not claim a vulnerability or compromise without supplied evidence.

## Current status

The legacy project successfully trained a Qwen 2.5 3B LoRA adapter but used only 34 seed records, applied loss to system/user tokens, had no held-out evaluation, and used a different inference prompt. This repository now provides the reproducible foundation to correct those issues. The initial 34 records remain a seed corpus and are all marked `needs_expert_review`; they are suitable for pipeline smoke tests only.

The recommended first measured target is `Qwen/Qwen2.5-7B-Instruct` with QLoRA. Keep `Qwen/Qwen2.5-3B-Instruct` as a fast baseline. Test Qwen3 8B only after recording a compatible environment and benchmark result. See [architecture](docs/architecture.md) and the [model card](docs/model-card.md).

The delivery sequence and remaining gates are in the [implementation roadmap](docs/implementation-roadmap.md).

## Installation

Use a GPU Python environment compatible with your CUDA driver. Kaggle's image already provides PyTorch and CUDA; elsewhere obtain the matching CUDA wheel from the PyTorch index before installing the remaining pinned packages:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.lock
```

Do not put API tokens in notebooks or files. Use your platform's secret manager or a local ignored `.env` copied from `.env.example`. If `kaggle.txt` was ever shared or committed, revoke its token first.

## Data workflow

Raw source files are immutable audit inputs. `merged_dataset.jsonl` is the exact deduplicated union of the four smaller raw files.

```bash
python -m scripts.build_dataset
pytest -q
```

This creates canonical split files and `reports/dataset_quality.json`. Splits are grouped by scenario family to avoid obvious technique leakage. Review each canonical record, set `metadata.review_status` to `approved`, add provenance/licence details, then rerun validation. Do not set approval automatically.

## Training

```bash
# Real run: all examples must be expert-approved.
python -m scripts.train_adapter --config configs/train.example.json

# Pipeline-only smoke run against unapproved seed data; never use its adapter as a quality claim.
python -m scripts.train_adapter --config configs/train.example.json --allow-pending-review

# Two T4 GPUs, if Accelerate is configured for your environment.
accelerate launch --num_processes 2 -m scripts.train_adapter --config configs/train.example.json
```

The trainer uses prompt/completion records and `completion_only_loss=True`, so the target loss is limited to the assistant answer. It lets `SFTTrainer` attach LoRA exactly once, saves resumable checkpoints, validates during training, uses a fixed seed, and writes a training manifest.

## Local knowledge base and CLI

```bash
python -m security_assistant.cli kb-ingest docs/architecture.md \
  --title "Local architecture" --source-url "local://architecture" \
  --source-version "0.1" --trust-level reviewed

python -m security_assistant.cli kb-search "QLoRA evidence"

python -m security_assistant.cli assess "Interpret this HTTP response" --mode web \
  --evidence-file evidence.txt --dry-run

python -m security_assistant.cli assess "Assess the supplied LDAP evidence" \
  --mode active-directory --adapter outputs/qwen25-7b-security-lora
```

The KB is local SQLite FTS5 with hash deduplication, source version, retrieval date, and raw/reviewed labels. It is a transparent baseline; add embeddings only after measuring retrieval quality. Supplied files and retrieved text are explicitly marked untrusted in the model prompt.

Create a reusable assessment context before attaching sensitive evidence:

```bash
python -m security_assistant.cli assessment-create --name "Staging review" --mode web \
  --scope-file configs/scope.example.json
python -m security_assistant.cli assessment-show ASSESSMENT_ID
```

## Evaluation

Capture one response file for each of: base model, prompted base, adapter, and adapter+retrieval. Then score it with the commands in [evaluation baseline](docs/evaluation-baseline.md). Do not promote an adapter based on training loss or one sample response.

```bash
python -m scripts.run_benchmark --condition base --model Qwen/Qwen2.5-7B-Instruct \
  --output reports/responses/base.jsonl
python -m scripts.run_benchmark --condition prompted-base --model Qwen/Qwen2.5-7B-Instruct \
  --output reports/responses/prompted-base.jsonl
python -m scripts.run_benchmark --condition adapter --model Qwen/Qwen2.5-7B-Instruct \
  --adapter outputs/qwen25-7b-security-lora --output reports/responses/adapter.jsonl
python -m scripts.run_benchmark --condition adapter-rag --model Qwen/Qwen2.5-7B-Instruct \
  --adapter outputs/qwen25-7b-security-lora --output reports/responses/adapter-rag.jsonl
```

## Tool integration boundary

No active tooling is implemented. If added later, it must be a separate gateway enforcing documented scope, target allowlists, rate limits, command previews, immutable audit logs, and explicit human approval for intrusive actions. Never pass a generated command directly to a shell or testing tool.
