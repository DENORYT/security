# Contributing

Thanks for improving the portfolio.

## Before opening a change

1. Read [SAFETY.md](SAFETY.md).
2. Keep examples synthetic and non-sensitive.
3. Make behavior explicit in docs and tests.
4. Run:

   ```bash
   python -m unittest discover -s tests -v
   python scripts/validate.py
   ```

5. Review `git diff --check` and ensure generated files, credentials, and local runtime state are excluded.

## Change quality

Prefer small, understandable commits with a clear motivation. The projects use only the Python standard library on purpose; propose a justification before adding a dependency. Do not describe AI-assisted work as solely human-authored—keep project history and review notes accurate.
