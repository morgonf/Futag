"""Tests for the FuzzDataProviderGenerator class."""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from futag.fdp_generator import FuzzDataProviderGenerator


@pytest.fixture
def fdp_generator(tmp_futag_package, tmp_library_root):
    from futag.toolchain import ToolchainConfig
    tc = ToolchainConfig.from_futag_llvm(tmp_futag_package)
    return FuzzDataProviderGenerator(tmp_library_root, toolchain=tc)


class TestFDPProperties:
    def test_supports_c_false(self, fdp_generator):
        assert fdp_generator.supports_c is False

    def test_needs_buffer_check_false(self, fdp_generator):
        assert fdp_generator.needs_buffer_check is False

    def test_default_headers_includes_fdp(self, fdp_generator):
        assert "fuzzer/FuzzedDataProvider.h" in fdp_generator.default_headers

    def test_harness_preamble_has_provider(self, fdp_generator):
        assert "FuzzedDataProvider" in fdp_generator.harness_preamble


class TestFDPGenBuiltin:
    def test_int_uses_consume_integral(self, fdp_generator):
        result = fdp_generator._gen_builtin("x", {"type_name": "int"})
        assert any("ConsumeIntegral<int>" in line for line in result["gen_lines"])
        assert result["buffer_size"] == []

    def test_float_uses_consume_floating_point(self, fdp_generator):
        result = fdp_generator._gen_builtin("x", {"type_name": "float"})
        assert any("ConsumeFloatingPoint<float>" in line for line in result["gen_lines"])

    def test_double_uses_consume_floating_point(self, fdp_generator):
        result = fdp_generator._gen_builtin("x", {"type_name": "double"})
        assert any("ConsumeFloatingPoint<double>" in line for line in result["gen_lines"])


class TestFDPGenCstring:
    def test_uses_consume_random_length_string(self, fdp_generator):
        result = fdp_generator._gen_cstring("s", {"type_name": "const char *", "local_qualifier": ""}, 1)
        assert any("ConsumeRandomLengthString" in line for line in result["gen_lines"])
        assert result["gen_free"] == []


class TestFdpWritableString:
    """Output buffers (char *dst, unsigned char *dst) must not be initialized
    from std::string::c_str(), which is const and does not compile."""

    def _gen(self, fdp_generator, type_name):
        info = {"type_name": type_name, "base_type_name": type_name, "local_qualifier": "", "gen_type": 1, "length": 0}
        return "".join(fdp_generator._gen_cstring("str_dst", info, 1)["gen_lines"])

    def test_mutable_char_uses_buffer(self, fdp_generator):
        code = self._gen(fdp_generator, "char *")
        assert "std::vector<char> str_dst_buf(" in code
        assert "str_dst = reinterpret_cast<char *>(str_dst_buf.data());" in code
        assert ".c_str()" not in code

    def test_unsigned_char_cast(self, fdp_generator):
        code = self._gen(fdp_generator, "unsigned char *")
        assert "reinterpret_cast<unsigned char *>(str_dst_buf.data())" in code

    def test_const_char_points_into_string(self, fdp_generator):
        code = self._gen(fdp_generator, "const char *")
        assert "reinterpret_cast<const char *>(str_dst_fdp.c_str())" in code


class TestFdpInputFile:
    """A file path parameter gets a file whose content comes from the provider."""

    def _gen(self, fdp_generator, type_name="const char *"):
        info = {"type_name": type_name, "base_type_name": "char", "local_qualifier": "", "gen_type": 1, "length": 0}
        fdp_generator.state.file_idx = 1
        return fdp_generator._gen_input_file("f_fname0", info)

    def test_content_from_provider(self, fdp_generator):
        code = "".join(self._gen(fdp_generator)["gen_lines"])
        assert "f_fname0_content = provider.ConsumeRandomLengthString();" in code
        assert "futag_pos" not in code and "file_size" not in code
        assert "fwrite(f_fname0_content.data(), 1, f_fname0_content.size(), fp_0);" in code
        assert "const char * f_fname0 = f_fname0_path;" in code

    def test_name_per_process_and_removed(self, fdp_generator):
        r = self._gen(fdp_generator)
        assert "getpid()" in "".join(r["gen_lines"])
        assert "<unistd.h>" in fdp_generator.state.header
        assert r["gen_free"] == ["remove(f_fname0_path);\n"]
