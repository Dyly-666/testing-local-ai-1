"""QLoRA training utilities with completion-only supervision."""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from security_assistant.prompts import assessment_prompt


@dataclass
class TrainConfig:
    base_model: str = "Qwen/Qwen2.5-7B-Instruct"
    train_file: str = "data/canonical/train.jsonl"
    validation_file: str = "data/canonical/validation.jsonl"
    output_dir: str = "outputs/qwen25-7b-security-lora"
    max_seq_length: int = 4096
    epochs: float = 2.0
    learning_rate: float = 1e-4
    per_device_batch_size: int = 1
    gradient_accumulation_steps: int = 8
    lora_rank: int = 32
    lora_alpha: int = 64
    lora_dropout: float = 0.05
    seed: int = 42
    save_steps: int = 50
    eval_steps: int = 50
    warmup_ratio: float = 0.03

    @classmethod
    def from_file(cls, path: str) -> "TrainConfig":
        values = json.loads(Path(path).read_text(encoding="utf-8"))
        allowed = set(cls.__dataclass_fields__)
        unknown = set(values) - allowed
        if unknown:
            raise ValueError(f"Unknown training config keys: {sorted(unknown)}")
        return cls(**values)


def load_approved_records(path: str, allow_pending_review: bool) -> list[dict[str, Any]]:
    rows = []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        row = json.loads(line)
        status = row.get("metadata", {}).get("review_status")
        if status != "approved" and not allow_pending_review:
            raise ValueError(
                f"{path}:{number} has review_status={status!r}. "
                "Expert-approve data before training, or use --allow-pending-review only for a smoke run."
            )
        if [message.get("role") for message in row.get("messages", [])] != ["system", "user", "assistant"]:
            raise ValueError(f"{path}:{number} is not a single-turn conversational record")
        rows.append(row)
    if not rows:
        raise ValueError(f"No records loaded from {path}")
    return rows


def prompt_completion_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Use TRL's conversational prompt-completion schema.

    `completion_only_loss=True` masks system and user tokens, including the chat
    template tokens belonging to the prompt. This is more robust than manually
    guessing token offsets for a model-specific chat template.
    """
    prepared = []
    for i, row in enumerate(rows):
        question = row["messages"][1]["content"]
        domain = row.get("metadata", {}).get("domain", "web_application")
        mode = "active-directory" if domain == "active_directory" else "web"
        # The same prompt builder is used by the local CLI. Empty evidence and
        # references are explicit for seed examples rather than silently absent.
        prepared.append(
            {
                "prompt": assessment_prompt(mode, question, "", ""),
                "completion": [row["messages"][2]],
                "id": row.get("id", f"example_{i}"),
            }
        )
    return prepared


def seed_everything(seed: int) -> None:
    random.seed(seed)
    try:
        import numpy as np

        np.random.seed(seed)
    except ImportError:
        pass
    import torch

    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False
