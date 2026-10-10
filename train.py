import os
import sys

# Force unbuffered output so logs stream in real time
os.environ["PYTHONUNBUFFERED"] = "1"
os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
os.environ["TRANSFORMERS_NO_ADVISORY_WARNINGS"] = "1"

import torch
from datasets import load_dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from trl import SFTTrainer, SFTConfig

def log(msg):
    print(msg, flush=True)

def main():
    model_id = "Qwen/Qwen2.5-3B-Instruct"
    dataset_file = "/content/security_audit_dataset.jsonl"
    output_dir = "/content/security_specialist_lora"

    log("=" * 60)
    log("Fine-Tuning Security Assessment Specialist on Colab T4 GPU")
    log(f"Base Model: {model_id}")
    log(f"Dataset: {dataset_file}")
    log(f"Output Directory: {output_dir}")
    log("=" * 60)

    # 1. Check GPU
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is not available.")
    log(f"Using GPU: {torch.cuda.get_device_name(0)}")
    log(f"Initial VRAM Allocated: {torch.cuda.memory_allocated(0) / 1e9:.2f} GB")

    # 2. Load Tokenizer
    log("\n[Step 1/5] Loading Tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"
    log("Tokenizer loaded.")

    # 3. Load Dataset and apply chat template
    log("\n[Step 2/5] Preparing Dataset...")
    dataset = load_dataset("json", data_files=dataset_file, split="train")
    log(f"Loaded {len(dataset)} examples.")

    tune_md = "/content/tune.md"
    if os.path.exists(tune_md):
        with open(tune_md, "r") as f:
            system_prompt = f.read().strip()
        log(f"Loaded system prompt from tune.md ({len(system_prompt)} chars)")
    else:
        system_prompt = None
        log("tune.md not found — using per-example system prompts")

    def format_prompts(example):
        if system_prompt:
            messages = [{"role": "system", "content": system_prompt}]
            messages += [m for m in example["messages"] if m["role"] != "system"]
        else:
            messages = example["messages"]
        return {"text": tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)}

    formatted_dataset = dataset.map(format_prompts)
    log("Dataset formatted with chat template.")

    # 4. Configure 4-bit Quantization (QLoRA)
    log("\n[Step 3/5] Loading 4-bit Quantized Base Model...")
    log("Downloading model weights (this may take 1-3 minutes)...")
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True,
    )

    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        quantization_config=bnb_config,
        device_map="auto",
        torch_dtype=torch.float16,
        trust_remote_code=True,
    )
    model.config.use_cache = False
    model = prepare_model_for_kbit_training(model)
    log(f"Model loaded. VRAM used: {torch.cuda.memory_allocated(0) / 1e9:.2f} GB")

    # 5. Configure LoRA
    log("\n[Step 4/5] Setting up LoRA Adapter...")
    peft_config = LoraConfig(
        r=16,
        lora_alpha=32,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    )
    model = get_peft_model(model, peft_config)
    model.print_trainable_parameters()

    # 6. SFT Training Arguments
    training_args = SFTConfig(
        output_dir="/content/training_checkpoints",
        num_train_epochs=3,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=4,
        learning_rate=2e-4,
        lr_scheduler_type="cosine",
        warmup_ratio=0.1,
        logging_steps=1,
        fp16=True,
        optim="paged_adamw_8bit",
        gradient_checkpointing=True,
        max_length=4096,
        dataset_text_field="text",
        save_strategy="no",
        report_to="none",
    )

    trainer = SFTTrainer(
        model=model,
        train_dataset=formatted_dataset,
        args=training_args,
        peft_config=peft_config,
    )

    # 7. Start Training
    log("\n[Step 5/5] Launching Fine-Tuning Loop...")
    log(f"Pre-training VRAM: {torch.cuda.memory_allocated(0) / 1e9:.2f} GB")
    train_result = trainer.train()

    log("\n========== Training Complete ==========")
    log(f"Global steps: {train_result.global_step}")
    log(f"Training loss: {train_result.training_loss:.4f}")
    log(f"Peak VRAM used: {torch.cuda.max_memory_allocated(0) / 1e9:.2f} GB")

    # 8. Save Adapter and Tokenizer
    log(f"\nSaving fine-tuned LoRA adapter to {output_dir}...")
    trainer.model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)
    log("LoRA adapter and tokenizer saved successfully!")
    log("DONE")

if __name__ == "__main__":
    main()
