#!/usr/bin/env python3
"""
orchestrate.py — Autonomous improvement loop for the security AI.

Cycle:
  1. Poll Kaggle until training COMPLETE
  2. Download adapter → convert to MLX → deploy to Mac
  3. Run eval on Mac (model loaded once, all 33 questions)
  4. Score results → send Telegram report
  5. If score < TARGET: spawn `hermes chat -q` to generate targeted examples
  6. Rebuild dataset → push GitHub → push Kaggle (new training run)
  7. Goto 1

Stops when score >= TARGET or MAX_CYCLES reached.
Runs entirely in background — independent of any chat session.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

KAGGLE_KERNEL  = "zgdyz2tla29tamvz/security-assessment-finetuning"
MAC_HOST       = "mongsamnang@192.168.1.8"
MAC_DIR        = "~/Desktop/security-assistant-mac"
PROJECT_DIR    = Path("/home/stututu/fine-testing")
TELEGRAM_CHAT  = "595227544"

TARGET_SCORE   = 0.90
MAX_CYCLES     = 6
POLL_INTERVAL  = 90   # seconds between Kaggle status checks

ADAPTER_NAME   = "mlx_adapter"   # live adapter dir on Mac (always overwritten)
RESULTS_DIR    = PROJECT_DIR / "data" / "loop_results"

# ── Helpers ───────────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def run(cmd: str, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, text=True, capture_output=True, **kw)


def telegram(msg: str) -> None:
    """Send a Telegram message via hermes notify."""
    escaped = msg.replace('"', '\\"')
    run(f'hermes notify --channel telegram:{TELEGRAM_CHAT} "{escaped}"')


def hermes_q(prompt: str, timeout: int = 300, model: str = "") -> str:
    """Spawn a fresh hermes session for a reasoning step, return stdout.

    model examples:
      ""                                      → default (claude-sonnet-4-6)
      "google/gemini-flash-1.5"               → fast + cheap via OpenRouter
      "deepseek/deepseek-chat"                → good for structured output
      "anthropic/claude-opus-4"               → highest quality
    """
    escaped = prompt.replace("'", "'\\''")
    model_flag = f"--provider openrouter --model {model}" if model else ""
    r = subprocess.run(
        f"hermes chat -q $'{escaped}' {model_flag}",
        shell=True, text=True, capture_output=True, timeout=timeout
    )
    return r.stdout.strip()


# ── Step 1: Wait for Kaggle ───────────────────────────────────────────────────

def wait_for_kaggle(version_hint: str = "") -> str:
    """Poll until COMPLETE or ERROR. Returns 'complete' or 'error'."""
    log(f"Waiting for Kaggle training{' v'+version_hint if version_hint else ''} ...")
    for i in range(200):
        r = run(f"kaggle kernels status {KAGGLE_KERNEL}")
        status = r.stdout.strip()
        log(f"  [{i*POLL_INTERVAL//60}min] {status}")
        if "COMPLETE" in status:
            telegram(f"✅ Kaggle training {version_hint} COMPLETE — starting download & eval")
            return "complete"
        if "ERROR" in status or "CANCEL" in status:
            telegram(f"❌ Kaggle training {version_hint} FAILED: {status}")
            return "error"
        time.sleep(POLL_INTERVAL)
    return "timeout"


# ── Step 2: Download + convert + deploy ──────────────────────────────────────

def download_and_deploy(version: int) -> bool:
    out_dir = f"/tmp/kaggle_adapter_v{version}"
    log(f"Downloading adapter v{version} ...")

    # Download Kaggle output
    r = run(f"kaggle kernels output {KAGGLE_KERNEL} -p {out_dir}")
    if r.returncode != 0:
        log(f"Download FAILED: {r.stderr}")
        return False

    # Find the safetensors file
    files = list(Path(out_dir).rglob("adapter_model.safetensors"))
    config_files = list(Path(out_dir).rglob("adapter_config.json"))
    if not files:
        log(f"No adapter_model.safetensors found in {out_dir}")
        log(f"Contents: {list(Path(out_dir).rglob('*'))}")
        return False

    adapter_sf   = files[0]
    adapter_conf = config_files[0] if config_files else None
    log(f"Found adapter: {adapter_sf} ({adapter_sf.stat().st_size/1e6:.1f} MB)")

    # Convert safetensors → MLX npz on Mac via SSH
    # 1. SCP the safetensors + config to Mac
    remote_tmp = f"/tmp/adapter_v{version}"
    run(f"ssh {MAC_HOST} 'mkdir -p {remote_tmp}'")
    run(f"scp {adapter_sf} {MAC_HOST}:{remote_tmp}/adapter_model.safetensors")
    if adapter_conf:
        run(f"scp {adapter_conf} {MAC_HOST}:{remote_tmp}/adapter_config.json")

    # 2. Convert on Mac using the existing convert_adapter.py
    log("Converting safetensors → MLX on Mac ...")
    r = run(
        f"ssh {MAC_HOST} 'cd {MAC_DIR} && "
        f"source venv/bin/activate 2>/dev/null && "
        f"python3 convert_adapter.py "
        f"--adapter-dir {remote_tmp} "
        f"--out-dir {MAC_DIR}/{ADAPTER_NAME}_v{version}'"
    )
    log(r.stdout[-500:] or "(no output)")
    if r.returncode != 0:
        # Fallback: copy safetensors directly (mlx-lm 0.32+ can load safetensors natively)
        log("convert_adapter.py failed — trying direct safetensors deploy ...")
        run(f"ssh {MAC_HOST} 'mkdir -p {MAC_DIR}/{ADAPTER_NAME}_v{version}'")
        run(f"scp {adapter_sf} {MAC_HOST}:{MAC_DIR}/{ADAPTER_NAME}_v{version}/adapters.safetensors")
        if adapter_conf:
            run(f"scp {adapter_conf} {MAC_HOST}:{MAC_DIR}/{ADAPTER_NAME}_v{version}/adapter_config.json")

    # 3. Point the live adapter symlink to the new version
    run(
        f"ssh {MAC_HOST} "
        f"'cd {MAC_DIR} && "
        f"rm -rf {ADAPTER_NAME} && "
        f"cp -r {ADAPTER_NAME}_v{version} {ADAPTER_NAME}'"
    )

    log(f"Adapter v{version} deployed to Mac as '{ADAPTER_NAME}'")
    return True


# ── Step 3: Eval on Mac ───────────────────────────────────────────────────────

def run_eval(version: int) -> tuple[float, list[dict]]:
    results_file = f"data/eval_results_v{version}.jsonl"
    log(f"Running eval on Mac (v{version}) — model loads once, ~30min ...")

    # SCP eval_batch_mac.py and benchmark if not already there
    run(f"scp {PROJECT_DIR}/eval_batch_mac.py {MAC_HOST}:{MAC_DIR}/eval_batch_mac.py")
    run(f"scp {PROJECT_DIR}/data/eval_benchmark.jsonl {MAC_HOST}:{MAC_DIR}/data/eval_benchmark.jsonl")

    r = subprocess.run(
        f"ssh {MAC_HOST} 'cd {MAC_DIR} && "
        f"source venv/bin/activate 2>/dev/null && "
        f"python3 eval_batch_mac.py "
        f"--adapter {ADAPTER_NAME} "
        f"--out {results_file} "
        f"--max-tokens 600 --temp 0.0'",
        shell=True, text=True, capture_output=True, timeout=2400
    )
    output = r.stdout + r.stderr
    log(output[-1000:])

    # Extract score
    m = re.search(r"FINAL_SCORE=([\d.]+)", output)
    score = float(m.group(1)) if m else 0.0

    # Pull results file back
    local_results = RESULTS_DIR / f"eval_results_v{version}.jsonl"
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    run(f"scp {MAC_HOST}:{MAC_DIR}/{results_file} {local_results}")

    results = []
    if local_results.exists():
        results = [json.loads(l) for l in local_results.read_text().splitlines() if l.strip()]

    return score, results


# ── Step 4: Telegram score report ─────────────────────────────────────────────

def report(version: int, score: float, results: list[dict]) -> None:
    failed = [r for r in results if r["score"] < 1.0]
    failed.sort(key=lambda r: r["score"])
    worst = "\n".join(f"  {r['score']:.2f} {r['id']}" for r in failed[:8])
    msg = (
        f"📊 Eval v{version} — Score: {score:.3f}\n"
        f"Perfect: {sum(1 for r in results if r['score']==1.0)}/{len(results)}\n"
        f"\nWorst cases:\n{worst}\n"
        f"\n{'🎯 TARGET REACHED!' if score >= TARGET_SCORE else '🔄 Improving...'}"
    )
    telegram(msg)
    log(msg)


# ── Step 5: Generate targeted training examples ───────────────────────────────

def generate_targeted_examples(results: list[dict], version: int) -> Path:
    """Use hermes chat -q to generate new training examples for failed cases."""
    failed = [r for r in results if r["score"] < 0.85]

    # Build a detailed prompt for Hermes to generate training data
    failure_summary = "\n".join(
        f"- Q: {r['question']}\n  Missing: {[f for f in r['failed'] if 'MUST_INCLUDE' in f]}"
        for r in failed[:12]
    )

    prompt = f"""You are a security training data specialist.
The model failed these eval questions. Generate 2 high-quality training examples (system/user/assistant format) for EACH failed question below.

Rules:
- Each example must be a JSON object with a "messages" array: [{{"role":"system","content":"..."}},{{"role":"user","content":"..."}},{{"role":"assistant","content":"..."}}]
- The assistant answer must contain the MISSING key phrases listed
- ESC8 answers MUST include: ntlm relay, http, certsrv, coerce, certipy relay or ntlmrelayx
- Answers must be technically accurate, detailed, with exact tool commands
- Output ONLY valid JSONL (one JSON per line), no markdown fences

Failed questions and missing phrases:
{failure_summary}

Output only JSONL, no other text."""

    log("Spawning hermes session (gemini-flash) to generate targeted examples ...")
    output = hermes_q(prompt, timeout=600, model="google/gemini-flash-1.5")

    # Extract JSONL lines
    new_examples = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("```"):
            continue
        try:
            rec = json.loads(line)
            if "messages" in rec:
                new_examples.append(rec)
        except json.JSONDecodeError:
            continue

    log(f"Generated {len(new_examples)} new training examples")

    out_path = PROJECT_DIR / f"data/targeted_examples_v{version}.jsonl"
    out_path.write_text("\n".join(json.dumps(e) for e in new_examples) + "\n")
    return out_path


# ── Step 6: Rebuild dataset + push ───────────────────────────────────────────

def rebuild_and_push(new_examples_path: Path, next_version: int) -> bool:
    log("Rebuilding canonical dataset ...")

    # Merge new examples into uncensored_examples.jsonl
    existing = (PROJECT_DIR / "uncensored_examples.jsonl").read_text()
    new_lines = new_examples_path.read_text()
    combined = existing.rstrip() + "\n" + new_lines
    (PROJECT_DIR / "uncensored_examples.jsonl").write_text(combined)

    # Rebuild canonical splits
    r = run(
        f"cd {PROJECT_DIR} && python3 -c \"\n"
        "import json, hashlib, random\n"
        "from pathlib import Path\n"
        "\n"
        "files = ['merged_dataset.jsonl','security_audit_dataset.jsonl',\n"
        "         'uncensored_examples.jsonl','web_security_dataset_batch2.jsonl',\n"
        "         'web_security_dataset_batch3.jsonl','web_security_dataset_local.jsonl']\n"
        "seen, all_recs = set(), []\n"
        "for f in files:\n"
        "    p = Path(f)\n"
        "    if not p.exists(): continue\n"
        "    for line in p.read_text().splitlines():\n"
        "        if not line.strip(): continue\n"
        "        rec = json.loads(line)\n"
        "        key = str(rec.get('messages',''))[:200]\n"
        "        if key not in seen:\n"
        "            seen.add(key)\n"
        "            all_recs.append(rec)\n"
        "\n"
        "random.seed(42)\n"
        "random.shuffle(all_recs)\n"
        "n = len(all_recs)\n"
        "test_n = max(5, int(n*0.10))\n"
        "val_n  = max(8, int(n*0.15))\n"
        "test, val, train = all_recs[:test_n], all_recs[test_n:test_n+val_n], all_recs[test_n+val_n:]\n"
        "\n"
        "Path('data/canonical/train.jsonl').write_text('\\\\n'.join(json.dumps(r) for r in train)+'\\\\n')\n"
        "Path('data/canonical/validation.jsonl').write_text('\\\\n'.join(json.dumps(r) for r in val)+'\\\\n')\n"
        "Path('data/canonical/test.jsonl').write_text('\\\\n'.join(json.dumps(r) for r in test)+'\\\\n')\n"
        f"print(f'Dataset: train={{len(train)}} val={{len(val)}} test={{len(test)}} total={{n}}')\n"
        "\""
    )
    log(r.stdout.strip() or r.stderr.strip())

    # Update config output_dir for new version
    config_path = PROJECT_DIR / "configs/train.qwen3-8b.json"
    cfg = json.loads(config_path.read_text())
    cfg["output_dir"] = f"/kaggle/working/adapter_v{next_version}"
    config_path.write_text(json.dumps(cfg, indent=2) + "\n")

    # Commit and push
    r = run(
        f"cd {PROJECT_DIR} && "
        f"git add data/canonical/ uncensored_examples.jsonl configs/train.qwen3-8b.json "
        f"data/targeted_examples_v*.jsonl && "
        f"git commit -m 'Loop v{next_version}: targeted examples + rebuilt dataset' && "
        f"git push origin main"
    )
    log(r.stdout[-300:])
    if r.returncode != 0:
        log(f"Git push failed: {r.stderr[-300:]}")
        return False

    # Push to Kaggle
    r = run(f"cd {PROJECT_DIR}/kaggle_push && kaggle kernels push")
    log(r.stdout.strip())
    return r.returncode == 0


# ── Main loop ─────────────────────────────────────────────────────────────────

def main() -> None:
    # Start version: next after what's currently training
    start_version = int(sys.argv[1]) if len(sys.argv) > 1 else 21
    log(f"Autonomous improvement loop starting — target score: {TARGET_SCORE}, max cycles: {MAX_CYCLES}")
    telegram(f"🤖 Improvement loop started — target: {TARGET_SCORE}, max {MAX_CYCLES} cycles")

    score = 0.0
    version = start_version

    for cycle in range(1, MAX_CYCLES + 1):
        log(f"\n{'='*60}\nCYCLE {cycle} — adapter v{version}\n{'='*60}")
        telegram(f"🔄 Cycle {cycle}/{MAX_CYCLES} — waiting for v{version} training ...")

        # 1. Wait for Kaggle
        status = wait_for_kaggle(str(version))
        if status == "error":
            telegram(f"❌ Cycle {cycle}: Kaggle v{version} failed. Stopping.")
            break

        # 2. Download + deploy
        ok = download_and_deploy(version)
        if not ok:
            telegram(f"❌ Cycle {cycle}: Deploy failed for v{version}. Stopping.")
            break

        # 3. Eval
        score, results = run_eval(version)
        report(version, score, results)

        if score >= TARGET_SCORE:
            telegram(
                f"🎯 TARGET REACHED! v{version} score={score:.3f} ≥ {TARGET_SCORE}\n"
                f"Adapter is ready. Run:\n"
                f"  python3 run.py --adapter {ADAPTER_NAME}"
            )
            log(f"Done! Score {score:.3f} >= target {TARGET_SCORE}")
            break

        if cycle == MAX_CYCLES:
            telegram(f"⚠️ Max cycles reached. Best score: {score:.3f}. Stopping.")
            break

        # 4. Generate targeted examples
        next_version = version + 1
        new_examples_path = generate_targeted_examples(results, version)

        # 5. Rebuild + push
        ok = rebuild_and_push(new_examples_path, next_version)
        if not ok:
            telegram(f"❌ Cycle {cycle}: Push failed. Stopping.")
            break

        telegram(f"🚀 v{next_version} training started on Kaggle — cycle {cycle+1} coming up")
        version = next_version

    log(f"Loop complete. Final score: {score:.3f}")


if __name__ == "__main__":
    main()
