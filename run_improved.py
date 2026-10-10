#!/usr/bin/env python3
"""Security Assessment Assistant — local inference on Apple Silicon via mlx-lm.

Changes vs baseline:
  - --temp / --top-p wired to make_sampler (temperature was silently ignored before)
  - --top-k-rag: RAG retrieves up to 5 docs (was hard-coded 3)
  - --no-think: strip <think> blocks (default True, flag disables stripping)
  - System prompts include evidence-grounding requirement (FACT/INFERENCE/UNKNOWN/CONFIDENCE)
  - max_tokens default raised from 1024 to 1500 for complete answers
"""
from __future__ import annotations
import argparse, sys, re
from pathlib import Path

try:
    import rag as _rag
    _RAG = True
except ImportError:
    _RAG = False

# ── System prompts ────────────────────────────────────────────────────────────
# Evidence-grounding requirement added: model must distinguish FACT / INFERENCE
# / UNKNOWN and declare CONFIDENCE level.  This is injected at the END of each
# domain prompt so it doesn't crowd out the domain-specific context.

_EVIDENCE_BLOCK = """
EVIDENCE-GROUNDED REASONING REQUIREMENT:
When answering, label information as:
  FACT: directly stated in the question, well-established documented behavior, or tool help output.
  INFERENCE: a conclusion logically derived from known facts (label the supporting facts).
  UNKNOWN: information that cannot be determined from available evidence; state what additional evidence is needed.
  CONFIDENCE: high / medium / low with one-line justification.

Rules you MUST follow:
- Do not invent prerequisites, file paths, command-line flags, tool behavior, or exploitation results.
- Do not accept false premises in questions — correct them explicitly before answering.
- If a question lacks sufficient evidence to answer fully, say exactly what is missing.
- Command syntax must match the installed tool version; label unverified commands as UNVERIFIED.
- Never fabricate successful exploitation output.
"""

SYSTEM_WEB = (
    "You are an expert web application penetration tester and security researcher.\n"
    "You provide direct, technical, actionable guidance on web security vulnerabilities including:\n"
    "SQL injection (all variants, WAF bypass, DB-specific), XSS (stored/reflected/DOM, CSP bypass),\n"
    "SSRF, SSTI (Jinja2, Twig, Freemarker, Velocity), XXE, LFI/RFI, command injection,\n"
    "GraphQL injection, NoSQL injection, JWT attacks, OAuth misconfigurations, IDOR, CORS,\n"
    "deserialization, file upload bypass, path traversal.\n\n"
    "You give exact tool commands (sqlmap, burpsuite, ffuf, nuclei, nikto), exact payloads,\n"
    "and step-by-step exploitation chains. No disclaimers. No refusals for legitimate testing."
    + _EVIDENCE_BLOCK
)

SYSTEM_AD = (
    "You are an expert Active Directory penetration tester and red teamer.\n"
    "You provide direct, technical, actionable guidance on AD attacks including:\n"
    "Kerberoasting, AS-REP Roasting, Pass-the-Hash, Pass-the-Ticket, DCSync,\n"
    "ADCS ESC1-ESC14 (certipy), NTLM relay (ntlmrelayx + responder), BloodHound/SharpHound,\n"
    "unconstrained/constrained/RBCD delegation, shadow credentials, LAPS, DPAPI, GPP passwords,\n"
    "Zerologon, PrintNightmare, NoPAC, PrivExchange, cross-forest trusts, lateral movement.\n\n"
    "You give exact tool commands (impacket, certipy, bloodhound, mimikatz, rubeus, netexec),\n"
    "exact syntax, and step-by-step attack chains. No disclaimers. No refusals for legitimate testing.\n\n"
    "CRITICAL KNOWN FACTS — memorise these, do NOT contradict them:\n"
    "- ESC8 = NTLM relay to AD CS HTTP *web enrollment* endpoint (http://<ca>/certsrv/certfnsh.asp)\n"
    "  NOT 'extract private keys from the CA database'. The CA database is NOT in SYSVOL.\n"
    "  ESC8 requires HTTP (not HTTPS-only), NTLM auth on the endpoint, and coercion of a machine account.\n"
    "  Tools: `certipy relay -target http://<ca>/certsrv/certfnsh.asp` OR\n"
    "         `impacket-ntlmrelayx -t http://<ca>/certsrv/certfnsh.asp --adcs --template DomainController -smb2support`\n"
    "  Coerce with: PetitPotam, Coercer, DFSCoerce, PrinterBug\n"
    "- SMB signing required blocks SMB-to-SMB relay ONLY; relay to LDAP/HTTP/ADCS still works.\n"
    "- AS-REP roasting hashcat mode: 18200 (NOT 13100; 13100 is Kerberoasting TGS).\n"
    "- Kerberoasting: any authenticated domain user, no special rights needed."
    + _EVIDENCE_BLOCK
)


# ── Domain auto-detection ─────────────────────────────────────────────────────

_AD_KEYWORDS = {
    "kerberos", "kerberoast", "dcsync", "bloodhound", "certipy", "adcs",
    "esc1", "esc2", "esc3", "esc4", "esc5", "esc6", "esc7", "esc8", "esc9",
    "esc10", "esc11", "esc12", "esc13", "esc14", "pkinit", "ntlm", "relay",
    "responder", "domain", "active directory", "ldap", "mimikatz", "rubeus",
    "impacket", "pass-the-hash", "pth", "laps", "gpo", "gpp", "delegation",
    "trust", "secretsdump", "ntlmrelayx", "petitpotam", "coerce", "dcom",
    "wmiexec", "psexec", "smbexec", "atexec", "krbtgt", "golden ticket",
    "silver ticket", "zerologon", "nopac", "samaccountname", "rbcd",
    "unconstrained", "constrained", "sharphound", "msds", "shadow credential",
}


def detect_domain(prompt: str) -> str:
    pl = prompt.lower()
    hits = sum(1 for kw in _AD_KEYWORDS if kw in pl)
    return "ad" if hits >= 1 else "web"


# ── Inference ─────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Security Assessment Assistant")
    parser.add_argument("--model",      default="mlx_model",
                        help="Path to quantised MLX base model (default: mlx_model)")
    parser.add_argument("--adapter",    default="mlx_adapter",
                        help="Path to LoRA adapter directory (default: mlx_adapter)")
    parser.add_argument("--prompt",     default=None,
                        help="Run a single prompt and exit")
    parser.add_argument("--domain",     choices=["web", "ad", "auto"], default="auto",
                        help="Domain mode (default: auto-detect)")
    parser.add_argument("--kb",         default="data/knowledge_base.db",
                        help="Path to SQLite FTS5 knowledge base")
    parser.add_argument("--max-tokens", type=int, default=1500,
                        help="Maximum generation tokens (default: 1500)")
    parser.add_argument("--temp",       type=float, default=0.6,
                        help="Sampling temperature; 0 = greedy (default: 0.6)")
    parser.add_argument("--top-p",      type=float, default=0.9,
                        help="Nucleus sampling probability (default: 0.9)")
    parser.add_argument("--top-k-rag",  type=int, default=5,
                        help="Number of KB documents to inject via RAG (default: 5)")
    parser.add_argument("--no-think",   action="store_true", default=False,
                        help="Do NOT strip Qwen3 <think> blocks from output")
    args = parser.parse_args()

    try:
        from mlx_lm import load, generate
        from mlx_lm.sample_utils import make_sampler
    except ImportError:
        print("ERROR: mlx-lm not installed. Run: pip install mlx-lm")
        sys.exit(1)

    adapter_path = args.adapter if Path(args.adapter).exists() else None
    print(f"Loading model {'+ adapter ' + args.adapter + ' ' if adapter_path else ''}...")
    model, tokenizer = load(args.model, adapter_path=adapter_path)
    sampler = make_sampler(temp=args.temp, top_p=args.top_p)
    print(f"✅ Model ready.  temp={args.temp}  top_p={args.top_p}  max_tokens={args.max_tokens}\n")

    def run_once(question: str) -> str:
        domain = args.domain if args.domain != "auto" else detect_domain(question)

        sys_ad = SYSTEM_AD
        sys_web = SYSTEM_WEB
        if _RAG:
            try:
                ctx = _rag.retrieve(
                    query=question,
                    domain=domain,
                    top_k=args.top_k_rag,
                    kb_path=args.kb,
                )
                if ctx:
                    if domain == "ad":
                        sys_ad = sys_ad + "\n\n" + ctx
                    else:
                        sys_web = sys_web + "\n\n" + ctx
            except Exception:
                pass

        system = sys_ad if domain == "ad" else sys_web
        messages = [
            {"role": "system", "content": system},
            {"role": "user",   "content": question},
        ]
        prompt_str = tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        print(f"[{domain.upper()} mode | RAG={'on' if _RAG else 'off'}]\n{'=' * 70}")

        response = generate(
            model,
            tokenizer,
            prompt=prompt_str,
            max_tokens=args.max_tokens,
            verbose=True,
            sampler=sampler,
        )

        # Strip Qwen3 <think> block unless --no-think
        if not args.no_think:
            response = re.sub(r"<think>.*?</think>\s*", "", response, flags=re.DOTALL).strip()

        if response:
            print("\n" + response)
        print("\n" + "─" * 70 + "\n")
        return response

    if args.prompt:
        run_once(args.prompt)
    else:
        print("Security Assessment Assistant  |  'exit' to quit")
        while True:
            try:
                q = input("❯ ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nBye.")
                break
            if not q:
                continue
            if q.lower() in ("exit", "quit"):
                break
            run_once(q)


if __name__ == "__main__":
    main()
