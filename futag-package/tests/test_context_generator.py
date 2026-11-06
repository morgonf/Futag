"""Regression tests for ContextGenerator on consumer-context fixtures.

See tests/fixtures/consumer_contexts/README.md for the fixture layout.
"""
import json
import os
import pathlib
import re
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
        db = json.loads((FIXTURES / "analysis.json").read_text())
        extra = FIXTURES / "cases" / case / "extra-functions.json"
        if extra.exists():
            db["functions"] += json.loads(extra.read_text())
        (lib / ".futag-analysis" / "futag-analysis-result.json").write_text(json.dumps(db))
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
    on_path = set(contexts[0]["cfg_blocks"])
    foreign = [c for c in contexts[1]["modifying_calls"]
               if c["name"] == "obj_modify" and c["cfg_block_ID"] not in on_path]
    assert foreign, "fixture must have a branch call off the first path"
    ctx = dict(contexts[0])
    # Inject the other branch's call: it is not on this path and must vanish.
    ctx["modifying_calls"] = ctx["modifying_calls"] + foreign
    got = statements(ContextGenerator._order_context_calls(ctx))
    assert foreign[0]["str_stmt"] not in got


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


REAL_CASES = [c for c in CASES if load_case(c)[1].get("source") != "handwritten"]
COMPLETE_REAL = [c for c in REAL_CASES if "known_loss" not in load_case(c)[1]]


@pytest.mark.parametrize("case", COMPLETE_REAL)
def test_generated_wrapper_keeps_order(make_generator, case):
    gen = make_generator(case)
    contexts, expected = load_case(case)
    gen.gen_context()
    stats = gen.context_stats
    assert stats["total"] == len(contexts)
    assert sum(v for k, v in stats.items() if k != "total") == stats["total"]
    assert stats["generated"] == len(contexts)
    sources = _generated_sources(gen)
    assert len(sources) == len(contexts)
    # Each wrapper must contain the calls of some expected sequence in order.
    for src in sources:
        ok = False
        for seq in expected["order"]:
            start, found = 0, True
            for stmt in seq:
                pos = src.find(stmt.split("(")[0] + "(", start)
                if pos == -1:
                    found = False
                    break
                start = pos + 1
            ok = ok or found
        assert ok, f"no expected call order in generated wrapper:\n{src}"


@pytest.mark.parametrize("case", REAL_CASES)
def test_generated_wrapper_is_plain_source(make_generator, case):
    """Regression for two analyzer-output defects: numeric literals arrived as
    one control byte, and consumer parameters (data, size) arrived as VARREF
    to names the wrapper never declares."""
    gen = make_generator(case)
    gen.gen_context()
    for src in _generated_sources(gen):
        assert not re.search(r"[\x00-\x08\x0b-\x1f]", src), "control byte in wrapper"
        assert not re.search(r"[(,]\s*(data|size|input)\s*[,)]", src), \
            f"undeclared consumer parameter passed through:\n{src}"


def test_const_kept_fuzzed_generated(make_generator):
    gen = make_generator("04_const_and_fuzzed")
    gen.gen_context()
    src = _generated_sources(gen)[0]
    # The enum constant stays fixed, input and data come from the fuzz buffer.
    assert re.search(r"obj_configure\(o ,MODE_SAFE ,str_input\d+", src), src
    assert "dyn_cstring_size" in src


def test_literals_spelled_as_c(make_generator):
    gen = make_generator("10_literals")
    gen.gen_context()
    src = _generated_sources(gen)[0]
    for line in ["= 300;", "= 2.5;", "= 44;", "= 2147483648;", '= "a\\"b\\n";']:
        assert line in src, f"{line!r} missing:\n{src}"


def test_duplicate_nested_producer_dropped():
    contexts, _ = load_case("11_producer_after_modify")
    got = statements(ContextGenerator._order_context_calls(contexts[0]))
    assert got.count("cfg_from(o)") == 1
