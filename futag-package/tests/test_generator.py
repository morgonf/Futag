"""Tests for the Generator class type generation methods."""
import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from futag.generator import Generator


@pytest.fixture
def generator(tmp_futag_package, tmp_library_root):
    """Create a Generator instance with mock paths."""
    from futag.toolchain import ToolchainConfig
    tc = ToolchainConfig.from_futag_llvm(tmp_futag_package)
    return Generator(tmp_library_root, toolchain=tc)


class TestGenBuiltin:
    def test_int_type(self, generator):
        result = generator._gen_builtin("x", {"type_name": "int"})
        assert "gen_lines" in result
        assert "gen_free" in result
        assert "buffer_size" in result
        assert any("memcpy" in line for line in result["gen_lines"])
        assert any("sizeof(int)" in line for line in result["gen_lines"])
        assert result["gen_free"] == []
        assert "sizeof(int)" in result["buffer_size"][0]

    def test_anonymous_namespace_stripped(self, generator):
        result = generator._gen_builtin("x", {"type_name": "(anonymous namespace)::MyType"})
        assert not any("(anonymous namespace)" in line for line in result["gen_lines"])

    def test_float_type(self, generator):
        result = generator._gen_builtin("x", {"type_name": "float"})
        assert any("sizeof(float)" in s for s in result["buffer_size"])


class TestGenCstring:
    def test_basic_cstring(self, generator):
        result = generator._gen_cstring("s", {
            "base_type_name": "char *",
            "type_name": "char *",
            "local_qualifier": ""
        }, 1)
        assert any("malloc" in line for line in result["gen_lines"])
        assert any("memcpy" in line for line in result["gen_lines"])
        assert any("free" in line for line in result["gen_free"])

    def test_const_cstring(self, generator):
        result = generator._gen_cstring("s", {
            "base_type_name": "char *",
            "type_name": "const char *",
            "local_qualifier": "const"
        }, 1)
        # Should have a reference variable
        assert any("rs" in line for line in result["gen_lines"])


class TestGenEnum:
    def test_c_enum(self, generator):
        enum_record = {"name": "Color", "qname": "Color", "enum_values": [
            {"field_name": "RED", "value": 0},
            {"field_name": "GREEN", "value": 1},
        ]}
        result = generator._gen_enum(enum_record, "e", {"type_name": "Color"}, {"compiler": "CC"})
        assert any("enum_index" in line for line in result["gen_lines"])
        assert any("% 2" in line for line in result["gen_lines"])

    def test_cxx_enum(self, generator):
        enum_record = {"name": "Color", "qname": "Color", "enum_values": [
            {"field_name": "RED", "value": 0},
        ]}
        result = generator._gen_enum(enum_record, "e", {"type_name": "Color"}, {"compiler": "CXX"})
        assert any("static_cast" in line for line in result["gen_lines"])


class TestGenArray:
    def test_basic_array(self, generator):
        result = generator._gen_array("arr", {
            "type_name": "int *", "base_type_name": "int", "length": 10
        })
        assert any("malloc" in line for line in result["gen_lines"])
        assert any("10" in line for line in result["gen_lines"])
        assert any("free" in line for line in result["gen_free"])


class TestGenVoid:
    def test_void_pointer(self, generator):
        result = generator._gen_void("v")
        assert any("NULL" in line for line in result["gen_lines"])
        assert result["gen_free"] == []
        assert result["buffer_size"] == []


class TestGenQualifier:
    def test_qualifier(self, generator):
        result = generator._gen_qualifier("q_x", "x", {"type_name": "const int"})
        assert any("q_x" in line and "x" in line for line in result["gen_lines"])


class TestGenPointer:
    def test_pointer(self, generator):
        result = generator._gen_pointer("p_x", "x", {"type_name": "int *"})
        assert any("& x" in line for line in result["gen_lines"])


class TestToolchainIntegration:
    def test_toolchain_kwarg(self, tmp_futag_package, tmp_library_root):
        """Pass toolchain explicitly via keyword arg."""
        from futag.toolchain import ToolchainConfig
        tc = ToolchainConfig.from_futag_llvm(tmp_futag_package)
        gen = Generator(tmp_library_root, toolchain=tc)
        assert gen.toolchain is tc
        assert gen.toolchain.clang is not None

    def test_generation_only_mode(self, tmp_library_root):
        """Generation-only: no toolchain, library_root is first arg."""
        gen = Generator(tmp_library_root)
        assert gen.toolchain.clang is None


class TestImplementationIncludes:
    """Unity builds include implementation files (.inl, .c) into a .c file;
    those must not be copied into generated wrappers."""

    def test_classification(self, generator):
        for h in ['"md5.inl"', '"part.c"', '<impl.inc>', '"x.CPP"']:
            assert generator._is_implementation_include(h), h
        for h in ['"civetweb.h"', '<stdio.h>', '<vector>', '"detail.hpp"']:
            assert not generator._is_implementation_include(h), h

    def test_gen_header_drops_inl(self, generator):
        generator.target_library["compiled_files"][0]["headers"] = ['"lib.h"', '"md5.inl"']
        fullpath = generator.target_library["compiled_files"][0]["filename"]
        lines = generator._gen_header(fullpath)
        assert '#include "lib.h"\n' in lines
        assert not any("md5.inl" in l for l in lines)


class TestSizeOutParameter:
    """A size_t * after a buffer (mg_base64_decode(src, len, dst, size_t *dst_len))
    must point to a variable, not be the size cast to a pointer."""

    def test_pointer_size_gets_address(self, generator):
        res = generator._gen_strsize("sz_dst_len", "size_t *", 2, "dyn_cstring_size")
        code = "".join(res["gen_lines"])
        assert "size_t sz_dst_len_v = (size_t) dyn_cstring_size[1];" in code
        assert "size_t * sz_dst_len = &sz_dst_len_v;" in code

    def test_plain_size_unchanged(self, generator):
        res = generator._gen_strsize("sz_len", "size_t", 1, "dyn_cstring_size")
        assert "size_t sz_len = (size_t) dyn_cstring_size[0];\n" in res["gen_lines"]


class TestPropagateParamUsage:
    """File path usage of an internal function reaches the public wrapper."""

    @staticmethod
    def _f(name, h, params, contexts=()):
        return {"name": name, "hash": h, "contexts": list(contexts),
                "params": [{"param_name": n, "param_usage": u} for n, u in params]}

    @staticmethod
    def _ctx(caller_hash, args):
        return {"caller_func_hash": caller_hash,
                "args_desc": [{"idx": i, "futag_type": t, "literal_value": v} for i, (t, v) in enumerate(args)]}

    def _run(self, functions):
        from futag.base_generator import BaseGenerator
        return BaseGenerator._propagate_param_usage(functions)

    def test_chain_of_wrappers(self):
        inner = self._f("inner", "1", [("path", "FILE_PATH_READ"), ("n", "UNKNOWN")],
                        [self._ctx("2", [("DECL_REF", "fname"), ("CONST_VAL", 0)])])
        mid = self._f("mid", "2", [("fname", "C_STRING")],
                      [self._ctx("3", [("DECL_REF", "name")])])
        top = self._f("top", "3", [("name", "UNKNOWN")])
        stats = self._run([inner, mid, top])
        assert mid["params"][0]["param_usage"] == "FILE_PATH_READ"
        assert top["params"][0]["param_usage"] == "FILE_PATH_READ"
        assert stats == {"propagated": 2, "contexts_without_caller": 0}

    def test_only_file_usage_is_carried(self):
        inner = self._f("inner", "1", [("s", "C_STRING")],
                        [self._ctx("2", [("DECL_REF", "x")])])
        outer = self._f("outer", "2", [("x", "UNKNOWN")])
        self._run([inner, outer])
        assert outer["params"][0]["param_usage"] == "UNKNOWN"

    def test_other_variable_or_extra_arg_is_ignored(self):
        inner = self._f("inner", "1", [("path", "FILE_PATH")],
                        [self._ctx("2", [("DECL_REF", "local"), ("DECL_REF", "x")])])
        outer = self._f("outer", "2", [("x", "UNKNOWN")])
        self._run([inner, outer])
        assert outer["params"][0]["param_usage"] == "UNKNOWN"

    def test_old_analysis_without_caller_is_counted(self):
        inner = self._f("inner", "1", [("path", "FILE_PATH")],
                        [{"args_desc": [{"idx": 0, "futag_type": "DECL_REF", "literal_value": "x"}]}])
        stats = self._run([inner])
        assert stats == {"propagated": 0, "contexts_without_caller": 1}


class TestCompileCommandsIndex:
    """compile_commands.json is parsed once, not on every lookup."""

    from futag.base_generator import BaseGenerator

    def _write(self, path, entries):
        import json
        path.write_text(json.dumps(entries))

    def test_lookup_and_single_parse(self, tmp_path, monkeypatch):
        import json
        from types import SimpleNamespace
        cc = tmp_path / "compile_commands.json"
        self._write(cc, [
            {"file": "/src/a.c", "command": "cc -c a.c", "directory": "/b"},
            {"file": "/src/b.cpp", "command": "c++ -c b.cpp", "directory": "/b"},
            {"file": "/src/a.c", "command": "second", "directory": "/b"},
        ])
        gen = SimpleNamespace(build_path=tmp_path)
        loads = []
        real_load = json.load
        monkeypatch.setattr(json, "load", lambda f: loads.append(1) or real_load(f))
        get = lambda p: self.BaseGenerator._get_compile_command(gen, p)
        gen._compile_commands_index = lambda: self.BaseGenerator._compile_commands_index(gen)
        a = get("/src//a.c")
        assert a == {"compiler": "CC", "command": "cc -c a.c", "file": "/src/a.c", "location": "/b"}
        assert get("/src/b.cpp")["compiler"] == "CXX"
        assert get("/src/none.c") == {"compiler": "CC", "command": "", "file": "/src/none.c", "location": ""}
        assert len(loads) == 1

    def test_no_compile_commands(self, tmp_path):
        from types import SimpleNamespace
        gen = SimpleNamespace(build_path=tmp_path)
        gen._compile_commands_index = lambda: self.BaseGenerator._compile_commands_index(gen)
        assert self.BaseGenerator._get_compile_command(gen, "/x/y.cc")["command"] == ""


class TestPreprocessorFlags:
    """Macros of the library's compile command reach the wrapper."""

    def test_extracts_defines_in_order(self):
        from futag.base_generator import BaseGenerator
        cmd = ('clang -DHAVE_CONFIG_H -D NAME=1 -I/x -O3 -UNDEBUG '
               '-DMSG="a b" -include cfg.h -fPIC -c f.c -o f.o')
        assert BaseGenerator._preprocessor_flags(cmd) == [
            "-DHAVE_CONFIG_H", "-D", "NAME=1", "-UNDEBUG", "-DMSG=a b",
            "-include", "cfg.h"]

    def test_empty_and_unbalanced(self):
        from futag.base_generator import BaseGenerator
        assert BaseGenerator._preprocessor_flags("") == []
        assert BaseGenerator._preprocessor_flags('cc -DA "-DB') == ["-DA"]
