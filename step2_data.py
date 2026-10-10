# @title Step 2: Load Tokenizer + Dataset (with tune.md system prompt)
model_id = "Qwen/Qwen2.5-3B-Instruct"

tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token
tokenizer.padding_side = "right"
print(f"Tokenizer loaded. Vocab size: {len(tokenizer)}")

# Load the full system prompt from tune.md
with open("/content/tune.md", "r") as f:
    system_prompt = f.read().strip()
print(f"System prompt loaded from tune.md ({len(system_prompt)} chars)")

dataset = load_dataset("json", data_files="/content/security_audit_dataset.jsonl", split="train")
print(f"Dataset loaded: {len(dataset)} examples")

def format_prompts(example):
    # Replace the per-example system prompt with the full tune.md persona
    messages = [{"role": "system", "content": system_prompt}]
    messages += [m for m in example["messages"] if m["role"] != "system"]
    return {"text": tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)}

formatted_dataset = dataset.map(format_prompts)
print(f"Formatted with tune.md system prompt. Sample length: {len(formatted_dataset[0]['text'])} chars")
