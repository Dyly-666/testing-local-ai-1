# @title Step 4: SFT Training + Save LoRA Adapter
import torch
from trl import SFTTrainer, SFTConfig

output_dir = "/content/security_specialist_lora"

print("[Step 4/5] Configuring SFT training...")
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

print(f"[Step 5/5] Starting training... Pre-training VRAM: {torch.cuda.memory_allocated(0) / 1e9:.2f} GB")
train_result = trainer.train()

print("\n========== Training Complete ==========")
print(f"Global steps:   {train_result.global_step}")
print(f"Training loss:  {train_result.training_loss:.4f}")
print(f"Peak VRAM:      {torch.cuda.max_memory_allocated(0) / 1e9:.2f} GB")

print(f"\nSaving LoRA adapter to {output_dir}...")
trainer.model.save_pretrained(output_dir)
tokenizer.save_pretrained(output_dir)
print("Adapter and tokenizer saved. DONE.")
