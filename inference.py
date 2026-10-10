import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

def main():
    base_model_id = "Qwen/Qwen2.5-3B-Instruct"
    adapter_path = "/content/security_specialist_lora"

    print("=" * 60)
    print("Testing Fine-Tuned Security Assessment Specialist")
    print(f"Base Model: {base_model_id}")
    print(f"Adapter: {adapter_path}")
    print("=" * 60)

    # 1. Load Tokenizer
    tokenizer = AutoTokenizer.from_pretrained(adapter_path, trust_remote_code=True)

    # 2. Load Base Model in 4-bit
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
    )

    base_model = AutoModelForCausalLM.from_pretrained(
        base_model_id,
        quantization_config=bnb_config,
        device_map="auto",
        torch_dtype=torch.float16,
        trust_remote_code=True,
    )

    # 3. Load LoRA Adapter
    print("Attaching fine-tuned LoRA adapter...")
    model = PeftModel.from_pretrained(base_model, adapter_path)
    model.eval()

    # 4. Evaluation Prompt
    system_prompt = """You are an expert Security Assessment and Vulnerability Auditing Specialist.
Your mission is to assist authorized security engineers, auditors, and defenders in evaluating system postures, identifying configuration weaknesses, validating security controls safely, and delivering structured, remediation-focused reports."""

    user_query = "Provide an audit procedure for testing whether an authorized internal OAuth 2.0 authorization server properly validates the redirect URI to prevent token leakage."

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_query}
    ]

    prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(prompt, return_tensors="pt").to("cuda")

    print("\n--- Generating Assessment Response ---")
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=512,
            temperature=0.3,
            top_p=0.9,
            repetition_penalty=1.1,
            do_sample=True,
        )

    response = tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
    print("\n" + response)
    print("\n" + "=" * 60)
    print("Inference test completed successfully.")

if __name__ == "__main__":
    main()
