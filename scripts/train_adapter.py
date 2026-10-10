#!/usr/bin/env python3
"""Train a QLoRA adapter; no model is pre-wrapped before SFTTrainer owns PEFT."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from security_assistant.training import TrainConfig, load_approved_records, prompt_completion_rows, seed_everything


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/train.example.json")
    parser.add_argument("--resume-from-checkpoint", default="auto")
    parser.add_argument("--allow-pending-review", action="store_true")
    args = parser.parse_args()
    config = TrainConfig.from_file(args.config)

    try:
        import torch
        from datasets import Dataset
        from peft import LoraConfig
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        from trl import SFTConfig, SFTTrainer
    except ModuleNotFoundError as error:
        raise SystemExit(
            "Missing training dependency: " + str(error) + ". "
            "Use the Kaggle GPU image or install the CUDA-compatible packages in requirements.lock."
        ) from error

    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is required for this QLoRA profile. Use a GPU runtime or a smaller CPU inference profile.")
    seed_everything(config.seed)
    train_rows = load_approved_records(config.train_file, args.allow_pending_review)
    validation_rows = load_approved_records(config.validation_file, args.allow_pending_review)
    train_dataset = Dataset.from_list(prompt_completion_rows(train_rows))
    validation_dataset = Dataset.from_list(prompt_completion_rows(validation_rows))

    tokenizer = AutoTokenizer.from_pretrained(config.base_model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"
    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True,
    )
    # In distributed training, Accelerate launches one process per GPU. Do not
    # use device_map="auto" for training; it silently turns a 2-GPU job into an
    # uneven model-placement job rather than data-parallel training.
    local_rank = int(__import__("os").environ.get("LOCAL_RANK", "0"))
    model = AutoModelForCausalLM.from_pretrained(
        config.base_model,
        quantization_config=bnb,
        torch_dtype=torch.float16,
        device_map={"": local_rank},
    )
    model.config.use_cache = False
    peft_config = LoraConfig(
        r=config.lora_rank,
        lora_alpha=config.lora_alpha,
        lora_dropout=config.lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    )
    training_args = SFTConfig(
        output_dir=config.output_dir,
        num_train_epochs=config.epochs,
        per_device_train_batch_size=config.per_device_batch_size,
        per_device_eval_batch_size=1,
        gradient_accumulation_steps=config.gradient_accumulation_steps,
        learning_rate=config.learning_rate,
        lr_scheduler_type="cosine",
        warmup_ratio=config.warmup_ratio,
        fp16=True,
        optim="paged_adamw_8bit",
        gradient_checkpointing=True,
        max_length=config.max_seq_length,
        completion_only_loss=True,
        eval_strategy="steps",
        eval_steps=config.eval_steps,
        save_strategy="steps",
        save_steps=config.save_steps,
        save_total_limit=2,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        logging_steps=1,
        report_to="none",
        seed=config.seed,
    )
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=validation_dataset,
        processing_class=tokenizer,
        peft_config=peft_config,
    )
    resume = None if args.resume_from_checkpoint == "none" else args.resume_from_checkpoint
    if resume == "auto":
        from transformers.trainer_utils import get_last_checkpoint

        resume = get_last_checkpoint(config.output_dir) if Path(config.output_dir).exists() else None
    result = trainer.train(resume_from_checkpoint=resume)
    trainer.save_model(config.output_dir)
    tokenizer.save_pretrained(config.output_dir)
    manifest = {"config": config.__dict__, "train_examples": len(train_rows), "validation_examples": len(validation_rows), "metrics": result.metrics}
    Path(config.output_dir, "training_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result.metrics, sort_keys=True))


if __name__ == "__main__":
    main()
