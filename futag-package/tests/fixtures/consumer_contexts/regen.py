#!/usr/bin/env python3
"""Regenerate consumer-context fixtures with a real futag-llvm.

Usage: python3 regen.py /path/to/futag-llvm [workdir]

Builds library.c with FutagAnalyzer, runs FutagConsumerAnalyzer on every
cases/<name>/consumer.c whose expected.json does not say "handwritten", and
writes the results into a work directory (a temporary one by default). The
fixtures themselves are not overwritten: diff the output against them and
update by hand, a difference is a finding about the analyzer or the fixture.

Builder.build_makefile does not change into the library directory, so both
builds are started with that directory as cwd.
"""
import json
import os
import pathlib
import re
import shutil
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "src"))

from futag.preprocessor import Builder, ConsumerBuilder  # noqa: E402
from futag.toolchain import ToolchainConfig  # noqa: E402


def main():
    tc = ToolchainConfig.from_futag_llvm(sys.argv[1])
    work = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else tempfile.mkdtemp(prefix="futag-fixtures-"))
    lib = work / "lib"
    if lib.exists():
        shutil.rmtree(lib)
    lib.mkdir(parents=True)
    for name in ("library.h", "library.c", "Makefile"):
        shutil.copy(HERE / name, lib / name)
    os.chdir(lib)
    b = Builder(lib.as_posix(), clean=True, toolchain=tc, processes=2, log_to_console=False)
    b.auto_build()
    b.analyze()
    out = work / "out"
    out.mkdir(exist_ok=True)
    db = json.loads((lib / ".futag-analysis/futag-analysis-result.json").read_text().replace(str(lib), "/src"))
    for cf in db.get("compiled_files", []):
        cf["compiler_opts"] = re.sub(r"/tmp/\S*", "/tmp/futag-report", cf["compiler_opts"])
    (out / "analysis.json").write_text(json.dumps(db, indent=2))
    for case in sorted((HERE / "cases").iterdir()):
        exp = json.loads((case / "expected.json").read_text())
        src = case / "consumer.c"
        if exp.get("source") == "handwritten" or not src.exists():
            print(f"{case.name}: skipped ({exp.get('source', 'no consumer.c')})")
            continue
        cons = work / "consumers" / case.name
        if cons.exists():
            shutil.rmtree(cons)
        cons.mkdir(parents=True)
        (cons / "consumer.c").write_text(src.read_text().replace('"../../library.h"', '"library.h"'))
        (cons / "Makefile").write_text(
            f"CC ?= cc\nall: consumer.o\nconsumer.o: consumer.c\n\t$(CC) $(CFLAGS) -I{lib} -c consumer.c -o consumer.o\n")
        shutil.rmtree(lib / ".futag-consumer", ignore_errors=True)
        os.chdir(cons)
        cb = ConsumerBuilder(lib.as_posix(), cons.as_posix(), clean=True, toolchain=tc, processes=1,
                             log_to_console=False)
        cb.auto_build()
        cb.analyze()
        res = lib / ".futag-consumer/futag-contexts.json"
        if res.exists():
            text = res.read_text().replace(str(lib), "/src").replace(str(work / "consumers"), "/consumers")
            (out / f"{case.name}.json").write_text(text)
            print(f"{case.name}: {len(json.loads(text))} contexts")
        else:
            print(f"{case.name}: NO CONTEXTS")
    print("output:", out)


if __name__ == "__main__":
    main()
