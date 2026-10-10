#!/usr/bin/env python3
"""
eval_batch_mac.py — Run on the MAC (via SSH).
Loads the model ONCE, runs all benchmark questions, saves results.

Usage (on Mac):
    cd ~/Desktop/security-assistant-mac
    python3 eval_batch_mac.py --adapter mlx_adapter_v21 --out results_v21.jsonl

Output: JSONL with {id, domain, question, response, score, passed, failed}
"""
from __future__ import annotations
import argparse, json, re, sys, time
from pathlib import Path

BENCHMARK = Path("data/eval_benchmark.jsonl")

def score_response(case, response):
    if not response.strip():
        return 0.0, [], ["response_missing"]
    norm = response.lower()
    passed, failed = [], []
    for req in case["rubric"].get("must_include", []):
        (passed if req.lower() in norm else failed).append(f"MUST_INCLUDE:{req}")
    for forb in case["rubric"].get("must_not_include", []):
        (failed if forb.lower() in norm else passed).append(f"MUST_NOT_INCLUDE:{forb}")
    denom = len(passed) + len(failed)
    score = round(len(passed) / denom, 3) if denom else 0.0
    return score, passed, failed

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model",    default="mlx_model")
    ap.add_argument("--adapter",  default="mlx_adapter")
    ap.add_argument("--out",      default="data/eval_results.jsonl")
    ap.add_argument("--max-tokens", type=int, default=600)
    ap.add_argument("--temp",     type=float, default=0.0)
    ap.add_argument("--kb",       default="data/knowledge_base.db")
    args = ap.parse_args()

    try:
        from mlx_lm import load, generate
        from mlx_lm.sample_utils import make_sampler
    except ImportError:
        print("ERROR: mlx-lm not installed"); sys.exit(1)

    try:
        import rag as _rag; RAG = True
    except ImportError:
        RAG = False

    print(f"Loading model + adapter {args.adapter} ...", flush=True)
    from pathlib import Path as P
    adapter_path = args.adapter if P(args.adapter).exists() else None
    model, tokenizer = load(args.model, adapter_path=adapter_path)
    sampler = make_sampler(temp=args.temp)
    print(f"Model ready. RAG={'on' if RAG else 'off'}  temp={args.temp}", flush=True)

    SYSTEM_AD = (
        "You are an expert Active Directory penetration tester and red teamer.\n"
        "You provide direct, technical, actionable guidance on AD attacks including:\n"
        "Kerberoasting, AS-REP Roasting, Pass-the-Hash, Pass-the-Ticket, DCSync,\n"
        "ADCS ESC1-ESC14 (certipy), NTLM relay (ntlmrelayx + responder), BloodHound/SharpHound,\n"
        "unconstrained/constrained/RBCD delegation, shadow credentials, LAPS.\n\n"
        "You give exact tool commands and step-by-step attack chains. No disclaimers.\n\n"
        "CRITICAL FACTS:\n"
        "- ESC8 = NTLM relay to AD CS HTTP web enrollment endpoint (http://<ca>/certsrv/certfnsh.asp)\n"
        "  NOT private key extraction. CA database is NOT in SYSVOL.\n"
        "  Requires HTTP (not HTTPS), NTLM auth on endpoint, coercion (PetitPotam/Coercer).\n"
        "  Tools: certipy relay -target http://<ca>/certsrv/certfnsh.asp\n"
        "         OR impacket-ntlmrelayx -t http://<ca>/certsrv/certfnsh.asp --adcs --template DomainController -smb2support\n"
        "- SMB signing required blocks SMB-to-SMB relay ONLY. LDAP/HTTP/ADCS relay still works.\n"
        "- AS-REP roasting hashcat mode = 18200 (NOT 13100; 13100 = Kerberoasting TGS).\n"
        "- Kerberoasting: any authenticated domain user, no special rights needed."
    )
    SYSTEM_WEB = (
        "You are an expert web application penetration tester.\n"
        "You give exact tool commands, payloads, and step-by-step exploitation. No disclaimers."
    )

    cases = [json.loads(l) for l in BENCHMARK.read_text().splitlines() if l.strip()]
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    done_ids = set()
    if out_path.exists():
        for line in out_path.read_text().splitlines():
            if line.strip():
                done_ids.add(json.loads(line)["id"])

    remaining = [c for c in cases if c["id"] not in done_ids]
    print(f"Cases: {len(cases)} total, {len(done_ids)} done, {len(remaining)} to run", flush=True)

    _THINK = re.compile(r"<think>.*?</think>\s*", re.DOTALL)

    with out_path.open("a") as fout:
        for idx, case in enumerate(remaining, 1):
            domain = case.get("domain", "ad")
            question = case["question"]

            sys_prompt = SYSTEM_AD if domain == "ad" else SYSTEM_WEB
            if RAG:
                try:
                    ctx = _rag.retrieve(query=question, domain=domain, top_k=5, kb_path=args.kb)
                    if ctx:
                        sys_prompt = sys_prompt + "\n\n" + ctx
                except Exception:
                    pass

            messages = [
                {"role": "system", "content": sys_prompt},
                {"role": "user",   "content": question},
            ]
            prompt_str = tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )

            t0 = time.monotonic()
            response = generate(
                model, tokenizer,
                prompt=prompt_str,
                max_tokens=args.max_tokens,
                verbose=False,
                sampler=sampler,
            )
            duration = round(time.monotonic() - t0, 1)
            response = _THINK.sub("", response).strip()

            score, passed, failed = score_response(case, response)
            result = {
                "id": case["id"], "domain": domain, "question": question,
                "response": response, "score": score,
                "passed": passed, "failed": failed, "duration_s": duration,
            }
            fout.write(json.dumps(result) + "\n")
            fout.flush()

            bar = "█" * int(score * 20)
            print(f"[{idx:02d}/{len(remaining)}] {score:.2f} [{bar:<20}] {case['id']} ({duration}s)", flush=True)
            if failed:
                for f in failed:
                    print(f"   ✗ {f}", flush=True)

    # Final report
    all_results = [json.loads(l) for l in out_path.read_text().splitlines() if l.strip()]
    mean = round(sum(r["score"] for r in all_results) / len(all_results), 3)
    perfect = sum(1 for r in all_results if r["score"] == 1.0)
    print(f"\n{'='*60}")
    print(f"SCORE: {mean:.3f}  |  Perfect: {perfect}/{len(all_results)}")
    print(f"Results: {out_path}")
    # Print as single line for easy parsing by orchestrator
    print(f"FINAL_SCORE={mean}")

if __name__ == "__main__":
    main()
