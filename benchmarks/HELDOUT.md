# Held-out evaluation policy

`benchmarks/heldout/` measures the pattern set honestly. It is never
allowed to shape it.

- **Never opened while editing patterns.** No one reads
  `benchmarks/heldout/bipia.json` or `HELDOUT_RESULTS.md` while writing or
  widening a pattern in `src/patterns.ts`. If you're mid-edit on a pattern,
  don't run `npm run bench:heldout` to check your work — that's exactly
  the tuning this set exists to prevent.
- **No pattern PR may cite a held-out row.** A commit message, PR
  description, or code comment justifying a pattern change must not
  reference anything in `benchmarks/heldout/`. Cite `corpora/attacks.json`
  or the deepset public benchmark instead — those are the corpora patterns
  are allowed to be tuned against.
- **Overlap is removed automatically.** `run.ts`'s `checkOverlap()`
  exact-matches normalized held-out row text against every payload in
  `corpora/attacks.json` and every row in
  `corpora/deepset-prompt-injections.json`, and drops matches before
  scoring. The removed count is printed and written into the results file.
- **Results are regenerated only at release time**, not on every commit —
  running it more often than that is itself a form of tuning pressure.
  The normal CI workflow therefore does not run this command.
- **If it's ever used to tune anyway, it's retired.** The set is replaced
  with a new sample (different seed, or a different upstream dataset), and
  the retirement is noted here with the date and reason.

## Retirement log

_None yet._
