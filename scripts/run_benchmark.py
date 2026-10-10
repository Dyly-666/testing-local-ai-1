#!/usr/bin/env python3
"""Generate one reproducible response set for a benchmark condition."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from security_assistant.knowledge_base import KnowledgeBase
from security_assistant.prompts import assessment_prompt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--condition", choices=["base", "prompted-base", "adapter", "adapter-rag"], required=True)
    parser.add_argument("--model", default="Qwen/Qwen2.5-7B-Instruct")
    parser.add_argument("--adapter")
    parser.add_argument("--benchmark", default="data/benchmarks/held_out.jsonl")
    parser.add_argument("--knowledge-base", default="data/knowledge_base/security.sqlite3")
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-new-tokens", type=int, default=800)
    args = parser.parse_args()
    if args.condition.startswith("adapter") and not args.adapter:
        parser.error("--adapter is required for adapter conditions")

    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    tokenizer = AutoTokenizer.from_pretrained(args.adapter or args.model)
    model = AutoModelForCausalLM.from_pretrained(
        args.model, device_map="auto", quantization_config=BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4")
    )
    if args.adapter:
        model = PeftModel.from_pretrained(model, args.adapter)
    model.eval()
    kb = KnowledgeBase(args.knowledge_base)
    try:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8") as handle:
            for line in Path(args.benchmark).read_text(encoding="utf-8").splitlines():
                case = json.loads(line)
                references = ""
                if args.condition == "adapter-rag":
                    references = "\n".join(f"[{r.document_id}] {r.title}: {r.excerpt}" for r in kb.search(case["question"]))
                if args.condition == "base":
                    messages = [{"role": "user", "content": f"{case['question']}\n\nEvidence:\n{case['evidence']}"}]
                else:
                    messages = assessment_prompt(case["mode"], case["question"], case["evidence"], references)
                prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
                inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
                with torch.inference_mode():
                    tokens = model.generate(**inputs, max_new_tokens=args.max_new_tokens, do_sample=False, pad_token_id=tokenizer.eos_token_id)
                response = tokenizer.decode(tokens[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
                handle.write(json.dumps({"id": case["id"], "response": response}, ensure_ascii=False) + "\n")
    finally:
        kb.close()


if __name__ == "__main__":
    main()
