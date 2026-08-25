# VANTAGE CODE — find → reproduce → verify → receipt

Spike-0 lives in `receipts/dev/vantage-code-spike0-2026-08-23/`.

- `find.py` — Kimi K3 proposes a candidate and a pytest. Output is `dispatched`.
- `verify.py` — runs that pytest on buggy vs fixed. **No model.** Verdict is PROVEN or UNVERIFIED.
- `verify_repo.py` — same fence, against a real checkout (`from youtube_dl.utils import …`).
- `expand_board.py` — BugsInPy extractor. Stdlib prelude at seal-time. Does not reopen scored keys.
- `spike0.py` — orchestrates + controls.
- `seal.mjs` — appends findings to `@jourdanlabs/luna-ledger`.

The model is structurally forbidden from being the proof.
