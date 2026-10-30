# code-triage

A tiny static scanner for Python that flags the security bugs I keep
seeing in real code — SQL injection, shell injection, `eval` on user
input, pickle loads, hardcoded secrets, that sort of thing. Standard
library only, runs in milliseconds, no model call involved.

## Why I built this

This week Mistral put the weights of Large 4 online and pitched it hard
at coding and cyber defense, and Google's new Carbon model is being
handed to vetted defenders first. The whole conversation is "models that
find and fix flaws." I wanted to see how far you get before any of that
— just walking the AST and matching patterns. Turns out: further than
I expected, and the failures are more interesting than the successes.

The honest version of the result: on my little 24-snippet corpus it
scores a perfect precision/recall, which mostly tells you the corpus
is small and I wrote both sides of it. Point it at a real repo and
you'll get noise — composed queries that are actually safe, `shell=True`
with a hardcoded command, secrets that are test fixtures. That's the
actual lesson here. A pattern matcher is a triage filter, not a verdict.
It earns its keep by shrinking the pile a human (or a model) has to
read from thousands of lines to a dozen suspicious ones.

## What it catches

- SQL injection — `execute()` with a composed query and no parameters
- Shell injection — `os.system()` on a built string, `subprocess` with `shell=True`
- Code execution — `eval`/`exec` on non-constant input
- Unsafe deserialization — `pickle`, `marshal`, `yaml.load` without `SafeLoader`
- Hardcoded secrets — credential-looking names assigned a real-looking string
- Weak crypto — MD5/SHA1, `random` for security tokens
- The smaller stuff — `verify=False`, tar extraction without `filter=`, Flask `debug=True`

The clean cases matter as much as the catches: parameterized queries,
`os.environ` secrets, sha256, `SafeLoader`, and filtered extraction all
pass quietly. A scanner that cries wolf on the safe patterns gets
deleted on day one, so I tested those explicitly.

## How to run it

```bash
python cli.py path/to/your/code.py
python cli.py path/to/your/repo --fail-on medium   # CI-friendly, exit 1 on findings
python cli.py path/to/your/repo --json              # machine-readable output
python eval.py                                       # score against the labeled corpus
python -m unittest test_scanner -v                  # tests
```

Try it on the samples first:

```bash
python cli.py corpus_samples/vulnerable.py   # 4 findings, exit 1
python cli.py corpus_samples/clean.py        # clean, exit 0
```

## Where a model would slot in

`review.py` drafts the review prompt for a flagged snippet and stops
there — deliberately no API call, no key. The shape I'd actually use in
production is two stages: this scanner as the cheap filter, then a model
reading only the flagged snippets in context to decide what's genuinely
exploitable. That keeps the expensive step on 1% of the code instead of
100% of it. Wiring in a client is a TODO, not a feature I faked.

## Rough edges

- It's AST-only, so anything it can't see statically (queries built in
  another module, config loaded at runtime) it just misses. No dataflow
  analysis, no taint tracking across functions.
- The hardcoded-secret check is name-based, so a variable called
  `token` holding something innocent will get flagged. I'd rather tune
  that down with an allowlist than miss a real key.
- Only Python. Extending it to JS/TS would mean a second parser and I
  didn't want to half-do that.

## TODO

- [ ] Taint tracking across one function call deep (the obvious next step)
- [ ] An allowlist file for known-safe patterns per repo
- [ ] Actually wire a model reviewer into `review.py` and measure how
      much it cuts the false-positive rate on a real repo
- [ ] SARIF output so GitHub code scanning can pick it up
