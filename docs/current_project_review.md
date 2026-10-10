# Current project review

## Observed architecture

The original project is a single-turn QLoRA experiment around `Qwen/Qwen2.5-3B-Instruct`: JSONL examples are formatted with a long `tune.md` prompt, trained with 4-bit NF4 and rank-16 LoRA, then loaded by a separate inference script. The Kaggle notebook duplicates that logic and embeds the prompt/data as base64. The repository had no package manifest, test set, validation loop, checkpointing, reproducible configuration, or retrieval layer.

## Concrete evidence from the supplied Kaggle run

- The notebook wrote 34 examples and used an 11,546-character system prompt; a formatted sample was 13,588 characters.
- It trained 29,933,568 adapter parameters and saved successfully, with reported loss 1.4341 and peak allocated VRAM 8.11 GB.
- It loaded only `Tesla T4` in its visible device log. The original notebook did not use an Accelerate launch, so the `T4 x2` allocation was not demonstrated as data-parallel training.
- Inference printed an uncontrolled, repetitive list of parameter names. This is a quality failure. The log alone does not prove a single cause, but the tiny corpus, prompt dominance, full-sequence labels, and no held-out test are strong design causes to correct before further training.
- The `torchao` shared-library warnings appeared after installing a wheel incompatible with the container's Python/ABI. They did not stop inference. `torchao` is not required by this project and is omitted from the locked dependency set.

## Data review result

`merged_dataset.jsonl` contains exactly 34 unique records and is the union of `security_audit_dataset.jsonl` (9), `web_security_dataset_local.jsonl` (5), batch 2 (10), and batch 3 (10). The canonical build deduplicates these inputs by content hash. It found 32 Web and only 2 AD records; that is not sufficient to claim AD-specialist capability. The generated [review queue](seed_dataset_review.md) inventories every seed record. All remain `needs_expert_review`, and sixteen are flagged for unqualified confirmation language.

## Implementation decisions

1. Keep raw sources immutable; generate canonical data with provenance, labels, split group, review state, and hash.
2. Use leakage-aware scenario-family splits. The present corpus is too small to be a reliable validation set, but the mechanism prevents an obvious false result.
3. Use conversational prompt/completion examples and `completion_only_loss=True`, so only the assistant completion is supervised.
4. Let `SFTTrainer` attach PEFT once; do not pre-wrap the model and also pass `peft_config`.
5. Default the next measured run to Qwen 2.5 7B Instruct; retain 3B as a baseline, and gate Qwen3 8B adoption on the benchmark.
