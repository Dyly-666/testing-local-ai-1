# Evaluation baseline

No model-comparison result has been claimed yet. The previous Kaggle run is **not** an evaluation: it trained on 34 seed examples with full-sequence labels and then displayed one unscored generation that drifted into an implausibly long input-field list.

The held-out benchmark contains Web and AD evidence scenarios, negative cases, ambiguous evidence, and prompt-injection content. It is intentionally separate from the seed corpus. For each condition, save responses as JSONL (`{"id": "case-id", "response": "..."}`) and run the rubric scorer:

```bash
python -m scripts.evaluate --responses reports/responses/base.jsonl --report reports/evaluations/base.json
python -m scripts.evaluate --responses reports/responses/prompted-base.jsonl --report reports/evaluations/prompted-base.json
python -m scripts.evaluate --responses reports/responses/adapter.jsonl --report reports/evaluations/adapter.json
python -m scripts.evaluate --responses reports/responses/adapter-rag.jsonl --report reports/evaluations/adapter-rag.json
```

The automated score is deliberately narrow. An expert reviewer must additionally score technical correctness, evidence attribution, false-positive control, scope discipline, and remediation quality on a 1--5 rubric. A model is only a candidate improvement when it improves those measures without degrading prompt-injection or negative-case performance.
