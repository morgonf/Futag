# Consumer-context fixtures

Regression fixtures for `ContextGenerator`: how a consumer context
(`.futag-consumer/futag-contexts.json`) is linearized into a call sequence
and compiled into a fuzz target.

Layout:

- `library.h`. Synthetic library API shared by all cases.
- `analysis.json`. Analysis DB for that API, in the format the analyzer
  actually writes (`return_type` is a string, see `FutagAnalyzer18.cpp:250`).
- `cases/<NN_name>/consumer.c`. The consumer code a case represents. Line and
  column numbers in the case JSON refer to this file.
- `cases/<NN_name>/futag-contexts.json`. Contexts in the exact shape of
  `WriteContextToFile` (`FutagConsumerAnalyzer18.cpp`).
- `cases/<NN_name>/expected.json`. Expected call order per context
  (`order`, a list of `str_stmt` lists) and optional fields:
  `resolve` (statement to expected function hash), `stats` (expected
  `context_stats` after `gen_context`), `known_loss` (an analyzer loss the
  case documents. The test is marked xfail strict, so it starts failing
  loudly once the loss is fixed).

The JSON files are written by hand following the analyzer source, not
produced by a real `futag-llvm` run (no toolchain was available when they
were created). Once a toolchain is available, regenerate them from
`consumer.c` and diff against the hand-written versions. A difference is a
finding about either the analyzer or these fixtures.
