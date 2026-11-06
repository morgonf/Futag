# Consumer-context fixtures

Regression fixtures for `ContextGenerator`: how a consumer context
(`.futag-consumer/futag-contexts.json`) is linearized into a call sequence
and compiled into a fuzz target.

Layout:

- `library.h`, `library.c`, `Makefile`. Synthetic library API shared by all
  cases.
- `analysis.json`. Analysis DB of that library produced by `futag-llvm`
  18.1.8 (`FutagAnalyzer`), temporary paths replaced by `/src`.
- `cases/<NN_name>/consumer.c`. The consumer code a case represents. Line and
  column numbers in the case JSON refer to this file.
- `cases/<NN_name>/futag-contexts.json`. Output of `FutagConsumerAnalyzer`
  for that consumer.
- `cases/<NN_name>/expected.json`. `source` (the analyzer build, or
  `handwritten`), the expected call order per context (`order`, a list of
  `str_stmt` lists, in clang's pretty-printed form) and optional fields:
  `resolve` (statement to expected function hash), `stats` (expected
  `context_stats` after `gen_context`), `note`, `known_loss` (an analyzer
  loss the case documents, `order` then holds the ideal sequence and the
  order test is xfail strict, so it fails loudly once the loss is fixed).

Two cases are handwritten because the analyzer cannot produce them from this
C library: `08_cxx_overload` (C++ overloads, kept in `extra-functions.json`)
and `09_missing_definition` (a stale analysis DB).

To regenerate after a change in the analyzer:

    python3 regen.py /path/to/futag-llvm /tmp/futag-fixtures

The script writes into the work directory and does not touch the fixtures.
Diff its `out/` against them. A difference is a finding about either the
analyzer or the fixtures.
