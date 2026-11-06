"""Regression tests for ContextGenerator on consumer-context fixtures.

See tests/fixtures/consumer_contexts/README.md for the fixture layout.
"""
import json
import os
import pathlib
import shutil
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from futag.generator import ContextGenerator  # direct import is circular

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "consumer_contexts"
CASES = sorted(p.name for p in (FIXTURES / "cases").iterdir() if p.is_dir())


def load_case(name):
    d = FIXTURES / "cases" / name
    contexts = json.loads((d / "futag-contexts.json").read_text())
    expected = json.loads((d / "expected.json").read_text())
    return contexts, expected


def case_param(name):
    _, expected = load_case(name)
    marks = []
    if "known_loss" in expected:
        marks.append(pytest.mark.xfail(strict=True, reason=expected["known_loss"]))
    return pytest.param(name, marks=marks, id=name)


@pytest.fixture
def make_generator(tmp_path):
    """Build a ContextGenerator over the fixture analysis DB and one case."""
    def _make(case):
        lib = tmp_path / "lib"
        (lib / ".futag-analysis").mkdir(parents=True)
        (lib / ".futag-consumer").mkdir()
        (lib / ".futag-build").mkdir()
        (lib / ".futag-install").mkdir()
        shutil.copy(FIXTURES / "analysis.json",
                    lib / ".futag-analysis" / "futag-analysis-result.json")
        shutil.copy(FIXTURES / "cases" / case / "futag-contexts.json",
                    lib / ".futag-consumer" / "futag-contexts.json")
        (lib / ".futag-build" / "compile_commands.json").write_text("[]")
        return ContextGenerator(lib.as_posix(), log_to_console=False)
    return _make


def statements(sequence):
    return [item["call"]["str_stmt"] for item in sequence]


@pytest.mark.parametrize("case", [case_param(c) for c in CASES])
def test_call_order(case):
    contexts, expected = load_case(case)
    got = [statements(ContextGenerator._order_context_calls(c)) for c in contexts]
    assert got == expected["order"]


@pytest.mark.parametrize("case", CASES)
def test_init_vars_defined_before_use(case):
    """Every VARREF to a context variable follows the call that defines it."""
    contexts, _ = load_case(case)
    for ctx in contexts:
        defined = set(ctx["init_calls"])
        seen = set()
        for item in ContextGenerator._order_context_calls(ctx):
            for arg in item["call"]["args"]:
                if arg["init_type"] == 0 and arg["value"] in defined:
                    assert arg["value"] in seen or arg["value"] == item["var"], \
                        f"{arg['value']} used before definition in {item['call']['str_stmt']}"
            if item["var"]:
                seen.add(item["var"])


def test_off_path_calls_dropped():
    contexts, _ = load_case("05_branch_paths")
    ctx = dict(contexts[0])
    # Inject the other branch's call: it is not on this path and must vanish.
    ctx["modifying_calls"] = ctx["modifying_calls"] + contexts[1]["modifying_calls"][:1]
    got = statements(ContextGenerator._order_context_calls(ctx))
    assert "obj_modify(o, 2)" not in got


def test_overload_resolved_by_arity(make_generator):
    gen = make_generator("08_cxx_overload")
    contexts, expected = load_case("08_cxx_overload")
    for item in ContextGenerator._order_context_calls(contexts[0]):
        stmt = item["call"]["str_stmt"]
        if stmt in expected["resolve"]:
            func = gen._find_context_function(item["call"])
            assert func is not None and func["hash"] == expected["resolve"][stmt]


def test_too_few_args_not_resolved(make_generator):
    """Analyzer drops an argument it cannot model (indirect call), so a call
    with fewer args than params must not match instead of raising IndexError."""
    gen = make_generator("01_create_target")
    call = {"name": "obj_target", "qname": "obj_target",
            "args": [{"init_type": 0, "value": "o"}]}
    assert gen._find_context_function(call) is None


def test_missing_definition_skipped_and_counted(make_generator):
    gen = make_generator("09_missing_definition")
    _, expected = load_case("09_missing_definition")
    gen.gen_context()
    assert gen.context_stats == expected["stats"]
    assert not list(pathlib.Path(gen.tmp_output_path).rglob("*.cpp"))


def _generated_sources(gen):
    return [p.read_text() for p in pathlib.Path(gen.tmp_output_path).rglob("*.cpp")]


@pytest.mark.parametrize("case", ["02_interleaved_init_modify", "03_nested_producer", "04_const_and_fuzzed"])
def test_generated_wrapper_keeps_order(make_generator, case):
    gen = make_generator(case)
    contexts, expected = load_case(case)
    gen.gen_context()
    stats = gen.context_stats
    assert stats["total"] == len(contexts)
    assert sum(v for k, v in stats.items() if k != "total") == stats["total"]
    assert stats["generated"] == len(contexts)
    sources = _generated_sources(gen)
    assert len(sources) == 1
    src = sources[0]
    names = [s.split("(")[0] for s in expected["order"][0]]
    positions = []
    start = 0
    for n in names:
        pos = src.find(n + "(", start)
        assert pos != -1, f"{n} missing or out of order in generated wrapper:\n{src}"
        positions.append(pos)
        start = pos + 1


def test_const_kept_fuzzed_generated(make_generator):
    gen = make_generator("04_const_and_fuzzed")
    gen.gen_context()
    src = _generated_sources(gen)[0]
    assert "= MODE_SAFE;" in src
    # input (ARG_INIT_UNKNOWN) and data come from the fuzz buffer.
    assert "dyn_cstring_size" in src
