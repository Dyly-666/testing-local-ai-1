# @title Step 3: Load 4-bit Quantized Model + LoRA Config
import torch
from transformers import AutoModelForCausalLM, BitsAndBytesConfig
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training

model_id = "Qwen/Qwen2.5-3B-Instruct"

print("[Step 3/5] Loading 4-bit quantized model (may take 2-3 min)...")
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
print(f"Base model loaded. VRAM used: {torch.cuda.memory_allocated(0) / 1e9:.2f} GB")

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
print("LoRA adapter attached. Model ready for training.")
