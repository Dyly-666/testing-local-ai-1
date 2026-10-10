"""CLI for retrieval and local model-assisted assessment; it executes no tools."""

from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path

from security_assistant.context_store import AssessmentStore
from security_assistant.knowledge_base import KnowledgeBase
from security_assistant.prompts import assessment_prompt


def reference_text(results: list) -> str:
    return "\n".join(
        f"[{item.document_id}] {item.title} ({item.trust_level}, {item.confidence})\n{item.excerpt}\n{item.source_url}"
        for item in results
    )


def generate(model_id: str, adapter: str | None, messages: list[dict[str, str]], max_new_tokens: int, load_in_4bit: bool = True) -> str:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    tokenizer = AutoTokenizer.from_pretrained(adapter or model_id)
    quantization_config = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4") if load_in_4bit else None
    model = AutoModelForCausalLM.from_pretrained(
        model_id, torch_dtype="auto", device_map="auto", quantization_config=quantization_config
    )
    if adapter:
        from peft import PeftModel

        model = PeftModel.from_pretrained(model, adapter)
    prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    with torch.inference_mode():
        output = model.generate(**inputs, max_new_tokens=max_new_tokens, do_sample=False, pad_token_id=tokenizer.eos_token_id)
    return tokenizer.decode(output[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)


def main() -> None:
    parser = argparse.ArgumentParser(prog="security-assistant")
    sub = parser.add_subparsers(dest="command", required=True)
    ingest = sub.add_parser("kb-ingest")
    ingest.add_argument("file")
    ingest.add_argument("--title", required=True)
    ingest.add_argument("--source-url", required=True)
    ingest.add_argument("--source-version", default="unknown")
    ingest.add_argument("--trust-level", choices=["raw", "reviewed"], default="raw")
    search = sub.add_parser("kb-search")
    search.add_argument("query")
    search.add_argument("--reviewed-only", action="store_true")
    assess = sub.add_parser("assess")
    assess.add_argument("question")
    assess.add_argument("--mode", choices=["web", "active-directory"], required=True)
    assess.add_argument("--evidence-file")
    assess.add_argument("--model", default="Qwen/Qwen2.5-7B-Instruct")
    assess.add_argument("--adapter")
    assess.add_argument("--max-new-tokens", type=int, default=800)
    assess.add_argument("--load-in-4bit", action=argparse.BooleanOptionalAction, default=True)
    assess.add_argument("--dry-run", action="store_true")
    assess.add_argument("--assessment-id", help="Attach a pre-created authorized assessment context")
    create = sub.add_parser("assessment-create")
    create.add_argument("--name", required=True)
    create.add_argument("--mode", choices=["web", "active-directory"], required=True)
    create.add_argument("--scope-file", required=True, help="JSON scope with authorized_targets and constraints")
    show = sub.add_parser("assessment-show")
    show.add_argument("assessment_id")
    parser.add_argument("--knowledge-base", default="data/knowledge_base/security.sqlite3")
    parser.add_argument("--assessment-store", default="data/assessments.sqlite3")
    args = parser.parse_args()

    kb = KnowledgeBase(args.knowledge_base)
    store = AssessmentStore(args.assessment_store)
    try:
        if args.command == "kb-ingest":
            content = Path(args.file).read_text(encoding="utf-8")
            doc_id = kb.ingest(title=args.title, source_url=args.source_url, source_version=args.source_version,
                               retrieved_at=date.today().isoformat(), trust_level=args.trust_level, content=content)
            print(json.dumps({"document_id": doc_id, "status": "ingested_or_deduplicated"}))
        elif args.command == "kb-search":
            print(json.dumps([item.__dict__ for item in kb.search(args.query, reviewed_only=args.reviewed_only)], indent=2))
        elif args.command == "assessment-create":
            scope = json.loads(Path(args.scope_file).read_text(encoding="utf-8"))
            print(json.dumps({"assessment_id": store.create(args.name, args.mode, scope)}))
        elif args.command == "assessment-show":
            print(json.dumps(store.get(args.assessment_id), indent=2))
        else:
            evidence = Path(args.evidence_file).read_text(encoding="utf-8") if args.evidence_file else ""
            context = store.get(args.assessment_id) if args.assessment_id else None
            if context and context["mode"] != args.mode:
                raise ValueError("assessment mode does not match --mode")
            if context:
                evidence = "Authorized assessment context (trusted configuration):\n" + json.dumps(context["scope"], sort_keys=True) + "\n\n" + evidence
            sources = kb.search(args.question, reviewed_only=False)
            messages = assessment_prompt(args.mode, args.question, evidence, reference_text(sources))
            if args.dry_run:
                print(json.dumps({"messages": messages, "citations": [item.__dict__ for item in sources]}, indent=2))
            else:
                print(generate(args.model, args.adapter, messages, args.max_new_tokens, args.load_in_4bit))
                print("\nSources:\n" + reference_text(sources))
    finally:
        kb.close()
        store.close()


if __name__ == "__main__":
    main()
