# Copyright (c) 2023-2024 ISP RAS (https://www.ispras.ru)
# Licensed under the GNU General Public License v3.0
# See LICENSE file in the project root for full license text.

# **************************************************
# **      ______  __  __  ______  ___     ______  **
# **     / ____/ / / / / /_  __/ /   |   / ____/  **
# **    / /_    / / / /   / /   / /| |  / / __    **
# **   / __/   / /_/ /   / /   / ___ | / /_/ /    **
# **  /_/      \____/   /_/   /_/  |_| \____/     **
# **                                              **
# **     Fuzz target Automated Generator       **
# **             a tool of ISP RAS                **
# **************************************************
# ** This module is for generating context-aware  **
# ** fuzz-drivers using consumer usage contexts   **
# **************************************************

"""Futag ContextGenerator - context-aware fuzz target generation."""

import json
import logging
import pathlib
import copy
import sys

from futag.sysmsg import *
from futag.generator import Generator

logger = logging.getLogger(__name__)


class ContextGenerator(Generator):
    """Context-aware Futag Generator that uses consumer call contexts.

    Extends Generator with context-specific methods for generating fuzz
    targets based on how library functions are actually called in consumer
    code (call sequences, variable bindings, etc.).
    """

    def __init__(self, library_root: str,
                 target_type: int = LIBFUZZER,
                 db_json_file: str = ANALYSIS_FILE_PATH,
                 context_json_file: str = CONTEXT_FILE_PATH,
                 output_path=CONTEXT_FUZZ_DRIVER_PATH,
                 build_path=BUILD_PATH, install_path=INSTALL_PATH,
                 delimiter: str = '.', toolchain=None,
                 log_to_console: bool = True):
        """Constructor of ContextGenerator class.

        Args:
            library_root (str): path to the library root.
            target_type (int, optional): format of fuzz-drivers. Defaults to LIBFUZZER.
            db_json_file (str, optional): path to the analysis JSON file. Defaults to ANALYSIS_FILE_PATH.
            context_json_file (str, optional): path to the context JSON file. Defaults to CONTEXT_FILE_PATH.
            output_path: where to save fuzz-drivers. Defaults to CONTEXT_FUZZ_DRIVER_PATH.
            build_path: path to the build directory. Defaults to BUILD_PATH.
            install_path: path to the install directory. Defaults to INSTALL_PATH.
            delimiter (str): delimiter for function name mangling.

        Raises:
            SystemExit: on invalid paths or configuration.
        """
        super().__init__(
            library_root,
            target_type=target_type, json_file=db_json_file,
            output_path=output_path, build_path=build_path,
            install_path=install_path, delimiter=delimiter,
            toolchain=toolchain, log_to_console=log_to_console,
        )

        self.consumer_contexts = None
        self.total_context = []
        self.ctx_vars = set()
        self.enum_consts = None
        self.unbound_args = 0

        # Load context JSON
        if not pathlib.Path(context_json_file).exists():
            self.context_json_file = pathlib.Path(library_root).absolute() / CONTEXT_FILE_PATH
        else:
            self.context_json_file = pathlib.Path(context_json_file)

        if self.context_json_file.exists():
            with open(self.context_json_file.as_posix()) as f:
                self.consumer_contexts = json.load(f)
        else:
            sys.exit(INVALID_CONTEXT_FILE_PATH + " " +
                     self.context_json_file.as_posix())

    # ------------------------------------------------------------------ #
    #  Context-aware target function generation                           #
    # ------------------------------------------------------------------ #

    def _gen_context_target_function(self, call, func, param_id) -> bool:
        """Generate code for a single function call within a context.

        Unlike the base _gen_target_function, this method takes a ``call``
        dict that carries the variable binding and argument initialisation
        information extracted from the consumer context.

        Args:
            call (dict): context call info with "var" and "call" keys.
            func (dict): function definition from analysis JSON.
            param_id (int): current parameter index (recursive).

        Returns:
            bool: True if generation succeeded.
        """
        malloc_free = [
            "unsigned char *",
            "char *",
        ]
        if param_id == len(func['params']):
            if not self.gen_anonymous and "(anonymous namespace)" in func["qname"]:
                self.state.curr_func_log = f"This function is in anonymous namespace!"
                self.state.gen_this_function = False
            found_parent = None
            if func["func_type"] in [FUNC_CXXMETHOD, FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR]:
                # Search for parent class
                for r in self.target_library["records"]:
                    if r["hash"] == func["parent_hash"]:
                        found_parent = r
                        break
                if not found_parent:
                    self.state.gen_this_function = False

            param_list = []
            for arg in self.state.param_list:
                param_list.append(arg + " ")
            self.state.param_list = []
            gen_lines = []

            func_call = ""
            if call["var"]:
                func_call += func["return_type"] + " " + \
                    call["var"] + " = " + func["name"] + "("
                func_call += ",".join(param_list)
                func_call += ");\n"
                gen_lines.append(func_call)
                if func["return_type"] in malloc_free:
                    gen_lines.append("if(" + call["var"] + "){\n")
                    gen_lines.append("    free(" + call["var"] + ");\n")
                    gen_lines.append("    " + call["var"] + " = NULL;\n")
                    gen_lines.append("}\n")

            elif func["func_type"] in [FUNC_CXXMETHOD, FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR]:
                class_name = found_parent["qname"]
                if func["func_type"] in [FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR]:
                    gen_lines.append(
                        "    //declare the RECORD and call constructor\n")
                    func_call += "    " + \
                        class_name.replace(
                            "::(anonymous namespace)", "") + " futag_target" + "("
                    func_call += ",".join(param_list)
                    func_call += ");\n"
                    gen_lines.append(func_call)
                else:
                    # Search for default constructor
                    # TODO: add code for other constructors
                    found_default_constructor = False
                    for fu in self.target_library["functions"]:
                        if fu["parent_hash"] == func["parent_hash"] and fu["func_type"] == FUNC_DEFAULT_CONSTRUCTOR:
                            found_default_constructor = True

                    # TODO: add code for other constructors!!!
                    if not found_default_constructor:
                        self.state.gen_this_function = False
                        return False
                    gen_lines.append("//declare the RECORD first\n")
                    func_call += class_name + " futag_target;\n"
                    func_call += ",".join(param_list)
                    func_call += ");\n"
                    gen_lines.append(func_call)
                    func_call = ""
                    # call the method
                    gen_lines.append("//METHOD CALL\n")
                    func_call += "futag_target." + func["name"] + "("
                    func_call += ",".join(param_list)
                    func_call += ");\n"
                    gen_lines.append(func_call)
            else:
                gen_lines.append("//FUNCTION_CALL\n")

                if func["return_type"] in malloc_free:
                    func_call += func["return_type"] + \
                        " futag_target = " + func["qname"] + "("
                    func_call += ",".join(param_list)
                    func_call += ");\n"
                    gen_lines.append(func_call)
                    if func["return_type"] in malloc_free:
                        gen_lines.append("if(futag_target){\n")
                        gen_lines.append("    free(futag_target);\n")
                        gen_lines.append("    futag_target = NULL;\n")
                        gen_lines.append("}\n")

                else:
                    func_call += func["qname"] + "("
                    func_call += ",".join(param_list)
                    func_call += ");\n"
                    gen_lines.append(func_call)

            if self.state.gen_free:
                gen_lines.append("//FREE\n")
                for line in self.state.gen_free:
                    gen_lines.append(line)
                self.state.gen_free = []

            curr_gen = {
                "gen_lines": gen_lines,
                "gen_free": [],
                "buffer_size": []
            }
            self._append_gen_dict(curr_gen)

            return True

        curr_param = func["params"][param_id]
        if len(curr_param["gen_list"]) > 1:
            curr_name = "_" + curr_param["param_name"]
        else:
            curr_name = curr_param["param_name"]
        prev_param_name = curr_name + str(self.var_idx)
        curr_name = curr_name + str(self.var_idx)
        self.var_idx += 1
        gen_curr_param = True

        curr_gen = {}

        if len(curr_param["gen_list"]) == 0:
            self.state.gen_this_function = False
            return False
        arg = call["call"]["args"][param_id]
        init_type = arg["init_type"]
        if init_type == ARG_INIT_VARREF and not self._is_bound_name(arg["value"]):
            # A reference to something the context does not define, typically
            # a parameter of the consumer function (data, size). Emitting the
            # name verbatim gives an undeclared identifier, so the argument
            # is generated from the fuzz input instead.
            init_type = ARG_INIT_UNKNOWN
            self.unbound_args += 1
        if init_type == ARG_INIT_VARREF:
            curr_name = arg["value"]
            self.state.param_list += [curr_name]
            param_id += 1
            self._gen_context_target_function(call, func, param_id)
        elif init_type == ARG_INIT_CONST:
            self.state.param_list += [curr_name]

            curr_gen = {
                "gen_lines": [
                    curr_param["param_type"] + " " +
                    curr_name + " = " + arg["value"] + ";\n"
                ],
                "gen_free": [],
                "buffer_size": []
            }
            self._append_gen_dict(curr_gen)
            param_id += 1
            self._gen_context_target_function(call, func, param_id)
        elif curr_param["gen_list"][0]["gen_type"] in [GEN_BUILTIN, GEN_CSTRING, GEN_WSTRING, GEN_REFSTRING, GEN_CXXSTRING, GEN_ENUM, GEN_ARRAY, GEN_UNION, GEN_INPUT_FILE, GEN_OUTPUT_FILE, GEN_QUALIFIER, GEN_POINTER]:
            for gen_type_info in curr_param["gen_list"]:
                if gen_type_info["gen_type"] == GEN_BUILTIN:
                    # GEN FILE DESCRIPTOR
                    # GEN STRING SIZE
                    this_gen_size = False
                    if curr_param["param_usage"] in ["FILE_DESCRIPTOR"]:
                        curr_name = "fd_" + curr_name + \
                            str(self.state.file_idx)  # string_prefix
                        self.state.file_idx += 1
                        curr_gen = self._gen_file_descriptor(
                            curr_name, gen_type_info)
                        self._append_gen_dict(curr_gen)
                        break
                    elif param_id > 0 and (func["params"][param_id - 1]["gen_list"][0]["gen_type"] in [GEN_CSTRING, GEN_WSTRING, GEN_CXXSTRING] or curr_param["param_usage"] == "SIZE_FIELD"):
                        if gen_type_info["type_name"] in ["size_t", "unsigned char", "char", "int", "unsigned", "unsigned int", "short", "unsigned short", "short int", "unsigned short int"]:
                            dyn_size_idx = 0
                            array_name = ""
                            if func["params"][param_id - 1]["gen_list"][0]["gen_type"] == GEN_CSTRING:
                                dyn_size_idx = self.state.dyn_cstring_size_idx
                                array_name = "dyn_cstring_size"
                            elif func["params"][param_id - 1]["gen_list"][0]["gen_type"] == GEN_WSTRING:
                                dyn_size_idx = self.state.dyn_wstring_size_idx
                                array_name = "dyn_wstring_size"
                            else:
                                dyn_size_idx = self.state.dyn_cxxstring_size_idx
                                array_name = "dyn_cxxstring_size"

                            curr_name = "sz_" + curr_name  # size_prefix
                            curr_gen = self._gen_strsize(
                                curr_name, curr_param["param_type"], dyn_size_idx, array_name)
                            self._append_gen_dict(curr_gen)
                            this_gen_size = True
                            break
                    if not this_gen_size:
                        curr_name = "b_" + curr_name  # builtin_prefix
                        curr_gen = self._gen_builtin(curr_name, gen_type_info)
                        self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_CSTRING:
                    # GEN FILE NAME OR # GEN STRING
                    if (curr_param["param_usage"] in ["FILE_PATH_READ", "FILE_PATH_WRITE", "FILE_PATH_RW", "FILE_PATH"] or curr_param["param_name"] in ["filename", "file", "filepath"] or curr_param["param_name"].find('file') != -1 or curr_param["param_name"].find('File') != -1) and len(curr_param["gen_list"]) == 1:
                        curr_name = "f_" + curr_name  # string_prefix
                        self.state.file_idx += 1
                        curr_gen = self._gen_input_file(
                            curr_name, gen_type_info)
                    else:
                        # GEN STRING
                        curr_name = "str_" + curr_name  # string_prefix
                        self.state.dyn_cstring_size_idx += 1
                        curr_gen = self._gen_cstring(
                            curr_name, gen_type_info, self.state.dyn_cstring_size_idx)
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_REFSTRING:
                    # GEN FILE NAME OR # GEN STRING
                    if (curr_param["param_usage"] in ["FILE_PATH_READ", "FILE_PATH_WRITE", "FILE_PATH_RW", "FILE_PATH"] or curr_param["param_name"] in ["filename", "file", "filepath"] or curr_param["param_name"].find('file') != -1 or curr_param["param_name"].find('File') != -1) and len(curr_param["gen_list"]) == 1:
                        curr_name = "f_" + curr_name  # string_prefix
                        self.state.file_idx += 1
                        curr_gen = self._gen_input_file(
                            curr_name, gen_type_info)
                    else:
                        # GEN STRING
                        curr_name = "str_" + curr_name  # string_prefix
                        self.state.dyn_cstring_size_idx += 1
                        curr_gen = self._gen_cstring(
                            curr_name, gen_type_info, self.state.dyn_cstring_size_idx)
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_WSTRING:
                    # GEN FILE NAME OR # GEN STRING
                    if (curr_param["param_usage"] in ["FILE_PATH_READ", "FILE_PATH_WRITE", "FILE_PATH_RW", "FILE_PATH"] or curr_param["param_name"] in ["filename", "file", "filepath"] or curr_param["param_name"].find('file') != -1 or curr_param["param_name"].find('File') != -1) and len(curr_param["gen_list"]) == 1:
                        curr_name = "f_" + curr_name  # string_prefix
                        self.state.file_idx += 1
                        curr_gen = self._gen_input_file(
                            curr_name, gen_type_info)
                    else:
                        # GEN STRING
                        curr_name = "strw_" + curr_name  # string_prefix
                        self.state.dyn_wstring_size_idx += 1
                        curr_gen = self._gen_wstring(
                            curr_name, gen_type_info, self.state.dyn_wstring_size_idx)
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_CXXSTRING:
                    curr_name = "str_" + curr_name  # string_prefix
                    self.state.dyn_cxxstring_size_idx += 1
                    curr_gen = self._gen_cxxstring(
                        curr_name, gen_type_info, self.state.dyn_cxxstring_size_idx)
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_ENUM:  # GEN_ENUM
                    curr_name = "e_" + curr_name  # enum_prefix
                    found_enum = None
                    # search in enum list of analysis result:
                    for enum in self.target_library["enums"]:
                        if len(gen_type_info["type_name"].split(" ")) > 1:
                            if enum["qname"] == gen_type_info["type_name"].split(" ")[
                                    1]:
                                found_enum = enum
                                break
                        else:
                            if enum["qname"] == gen_type_info["type_name"]:
                                found_enum = enum
                                break
                    if not found_enum:
                        # search in typedef list of analysis result:
                        for typedef in self.target_library["typedefs"]:
                            if typedef["name"] == gen_type_info["type_name"]:
                                enum_hash = typedef["type_source_hash"]
                                for enum in self.target_library["enums"]:
                                    if enum["hash"] == enum_hash:
                                        found_enum = enum
                            break
                    if not found_enum:
                        self.state.curr_func_log += f"- Can not generate for enum: {str(gen_type_info)}\n"
                        gen_curr_param = False
                    else:
                        compiler_info = self._get_compile_command(
                            func["location"]["fullpath"])
                        curr_gen = self._gen_enum(
                            found_enum, curr_name, gen_type_info, compiler_info, self.gen_anonymous)
                        self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_UNION:
                    curr_name = "u_" + curr_name  # union_prefix
                    curr_gen = self._gen_union(curr_name, gen_type_info)
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_ARRAY:  # GEN_ARRAY
                    curr_name = "a_" + curr_name  # array_prefix
                    curr_gen = self._gen_array(curr_name, gen_type_info)
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_QUALIFIER:
                    curr_name = "q_" + curr_name  # qualifier_prefix
                    curr_gen = self._gen_qualifier(
                        curr_name, prev_param_name, gen_type_info)
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_POINTER:
                    curr_name = "p_" + curr_name  # qualifier_prefix
                    curr_gen = self._gen_pointer(
                        curr_name, prev_param_name, gen_type_info)
                    self._append_gen_dict(curr_gen)
                prev_param_name = curr_name
            if not gen_curr_param:
                self.state.gen_this_function = False
            self.state.gen_lines += ["\n"]
            self.state.param_list += [curr_name]
            param_id += 1
            self._gen_context_target_function(call, func, param_id)

        else:
            if curr_param["gen_list"][0]["gen_type"] == GEN_STRUCT:
                # 1. Search for function call that generate struct type
                # 2. If not found, find in typdef the derived type of current struct and then take the action of 1.
                # 3. If not found, find the struct definition, check if the struct is simple and manual generate

                curr_name = "s_" + curr_name  # struct_prefix
                # A variable of structure type can be initialized with other functions.
                result_search_return_type = self._search_return_types(
                    curr_param["gen_list"], func, self.target_library['functions'])

                if not result_search_return_type:
                    # A struct type may be defined with different name through typdef
                    result_search_typedefs = self._search_in_typedefs(
                        curr_param["gen_list"][0]["type_name"], self.target_library['typedefs'])
                    if result_search_typedefs:
                        typedef_gen_list = [{
                            "base_type_name": result_search_typedefs["underlying_type"],
                            "gen_type": GEN_STRUCT,
                            "gen_type_name": "_STRUCT",
                            "length": 0,
                            "local_qualifier": "",
                            "type_name": result_search_typedefs["name"]
                        }]
                        # Search typedef in return type of functions
                        result_search_typdef_return_type = self._search_return_types(
                            typedef_gen_list, func, self.target_library['functions'])
                        if result_search_typdef_return_type:
                            old_values = self._save_state()
                            for curr_return_func in result_search_typdef_return_type:
                                self.state.var_function_idx += 1
                                self.state.gen_lines += ["\n"]
                                self.state.param_list += [curr_name]
                                curr_gen = self._gen_var_function(
                                    curr_name, curr_return_func["function"])
                                self._add_header(self._get_function_header(
                                    func["location"]["fullpath"]))
                                self._append_gen_dict(curr_gen)
                                #!!!call recursive
                                param_id += 1
                                self._gen_context_target_function(
                                    call, func, param_id)
                                param_id -= 1
                                self._restore_state(old_values)
                        else:
                            found_struct = None
                            for record in self.target_library["records"]:
                                if len(curr_param["gen_list"][0]["type_name"].split(" ")) > 1 and record["type"] == STRUCT_RECORD and record["name"] == curr_param["gen_list"][0]["type_name"].split(" ")[1] and record["is_simple"]:
                                    found_struct = record
                                    break
                            if found_struct:
                                curr_gen = self._gen_struct(
                                    curr_name, record, curr_param["gen_list"][0])
                                self._append_gen_dict(curr_gen)
                            else:
                                _tmp = curr_param["gen_list"][0]
                                self.state.curr_func_log += f"- Could not generate for object: {str(_tmp)}. Could not find function call to generate this struct!\n"
                        gen_curr_param = False
                    else:
                        _tmp = curr_param["gen_list"][0]
                        self.state.curr_func_log += f"- Could not generate for object: {str(_tmp)}. Could not create function call to generate this struct, and the definition of struct not found!\n"
                        gen_curr_param = False
                else:
                    old_values = self._save_state()
                    for curr_return_func in result_search_return_type:
                        self.state.var_function_idx += 1
                        self.state.gen_lines += ["\n"]
                        self.state.param_list += [curr_name]
                        curr_gen = self._gen_var_function(
                            curr_name, curr_return_func["function"])
                        self._add_header(self._get_function_header(
                            func["location"]["fullpath"]))
                        self._append_gen_dict(curr_gen)
                        #!!!call recursive
                        param_id += 1
                        self._gen_context_target_function(call, func, param_id)
                        param_id -= 1
                        self._restore_state(old_values)

            if curr_param["gen_list"][0]["gen_type"] == GEN_CLASS:
                # 1. Search for function call that generate class type
                # 2. If not found, try to generate class through constructor/default constructor

                curr_name = "c_" + curr_name  # struct_prefix
                # A variable of structure type can be initialized with other functions.
                result_search_return_type = self._search_return_types(
                    curr_param["gen_list"], func, self.target_library['functions'])

                if not result_search_return_type:
                    found_class = None
                    for record in self.target_library["records"]:
                        if record["type"] == CLASS_RECORD and record["name"] == curr_param["gen_list"][0]["type_name"]:
                            found_class = record
                            break
                    if found_class:
                        curr_gen_list = self._gen_class(
                            curr_name, found_class)
                        old_values = self._save_state()
                        for curr_gen in curr_gen_list:
                            self._append_gen_dict(curr_gen)
                            #!!!call recursive
                            self.state.gen_lines += ["\n"]
                            self.state.param_list += [curr_name]
                            param_id += 1
                            self.state.var_function_idx += 1
                            self._gen_context_target_function(call, func, param_id)
                            param_id -= 1
                            self._restore_state(old_values)
                    else:
                        gen_type_info = curr_param["gen_list"][0]
                        self.state.curr_func_log += f"- Could not generate for object: {str(gen_type_info)}. Could not find function call to generate this class!\n"
                        gen_curr_param = False
                else:
                    old_values = self._save_state()
                    for curr_return_func in result_search_return_type:
                        self.state.var_function_idx += 1
                        self.state.gen_lines += ["\n"]
                        self.state.param_list += [curr_name]
                        curr_gen = self._gen_var_function(
                            curr_name, curr_return_func["function"])
                        self._add_header(self._get_function_header(
                            func["location"]["fullpath"]))
                        self._append_gen_dict(curr_gen)
                        #!!!call recursive
                        param_id += 1
                        self._gen_context_target_function(call, func, param_id)
                        param_id -= 1
                        self._restore_state(old_values)

            if curr_param["gen_list"][0]["gen_type"] in [GEN_INCOMPLETE, GEN_VOID, GEN_FUNCTION, GEN_UNKNOWN]:
                gen_type_info = curr_param["gen_list"][0]
                self.state.curr_func_log += f"- Can not generate for object: {str(gen_type_info)}\n"
                gen_curr_param = False

            if not gen_curr_param:
                self.state.gen_this_function = False
            self.state.gen_lines += ["\n"]
            self.state.param_list += [curr_name]
            param_id += 1
            self._gen_context_target_function(call, func, param_id)

    # ------------------------------------------------------------------ #
    #  Sort call expressions into CFG block order                         #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _order_context_calls(context) -> list:
        """Linearize one consumer context into an executable call sequence.

        Calls are ordered by CFG path order (``cfg_blocks``), then by source
        position (file, line, col) inside a block, so init and modifying
        calls keep their original interleaving.  A stable dependency pass
        then moves every call after the init calls whose variables it
        references via ARG_INIT_VARREF.  Source position alone is not
        enough: for ``x = f(g())`` the analyzer extracts ``g()`` into a
        synthetic FutagRefVar whose column is greater than the column of
        ``f``, and the JSON writer stores ``init_calls`` as a map, so key
        order carries no information.

        Calls whose block is not on the path are dropped, as before.

        Args:
            context (dict): one entry of futag-contexts.json.

        Returns:
            list: [{"var": str, "call": dict}, ...] in execution order.
        """
        cfg_blocks = context.get("cfg_blocks", [])
        block_rank = {}
        for idx, block in enumerate(cfg_blocks):
            block_rank.setdefault(block, idx)

        def as_int(value):
            try:
                return int(value)
            except (TypeError, ValueError):
                return 0

        items = []
        for var, call in context.get("init_calls", {}).items():
            items.append({"var": var, "call": call})
        for call in context.get("modifying_calls", []):
            items.append({"var": "", "call": call})

        items = [i for i in items if i["call"].get("cfg_block_ID") in block_rank]

        # A nested producer that takes the tracked variable, as in
        # attach(o, cfg_from(o)), is recorded twice: as a FutagRefVar init
        # call and as a modifying call of o. Both entries are the same
        # expression (same position and callee), so the modifying copy is
        # dropped, otherwise the wrapper would call the producer twice.
        def position(i):
            c = i["call"]
            return (c.get("file"), c.get("line"), c.get("col"), c.get("name"))
        init_positions = {position(i) for i in items if i["var"]}
        items = [i for i in items if i["var"] or position(i) not in init_positions]
        items.sort(key=lambda i: (
            block_rank[i["call"]["cfg_block_ID"]],
            str(i["call"].get("file", "")),
            as_int(i["call"].get("line")),
            as_int(i["call"].get("col")),
            0 if i["var"] else 1,
        ))

        defined = {i["var"] for i in items if i["var"]}

        def deps(item):
            return {
                arg.get("value") for arg in item["call"].get("args", [])
                if arg.get("init_type") == ARG_INIT_VARREF
                and arg.get("value") in defined
                and arg.get("value") != item["var"]
            }

        ordered = []
        emitted = set()
        pending = list(items)
        while pending:
            pick = None
            for pos, item in enumerate(pending):
                if deps(item) <= emitted:
                    pick = pos
                    break
            if pick is None:
                # Cyclic dependency: keep source order and report it.
                pick = 0
                logger.warning(
                    "Cyclic variable dependency in consumer context at %s",
                    pending[0]["call"].get("str_stmt", pending[0]["call"].get("name")))
            item = pending.pop(pick)
            ordered.append(item)
            if item["var"]:
                emitted.add(item["var"])
        return ordered

    def sort_callexprs(self):
        """Linearize all consumer contexts into call sequences.

        Processes consumer_contexts to produce total_context: a list of
        ordered call sequences ready for fuzz target generation.  See
        _order_context_calls for the ordering rules.

        Returns:
            bool: False if consumer_contexts is empty/None.
        """
        if not self.consumer_contexts:
            return False

        total_context = []
        for context in self.consumer_contexts:
            logger.info("====== Context: ")
            logger.info("cfg_blocks: %s", context.get("cfg_blocks"))
            total_context.append(self._order_context_calls(context))
        self.total_context = total_context
        return True

    def _is_bound_name(self, name) -> bool:
        """True if a VARREF name is defined by the current context or is an
        enum constant known to the analysis DB (consumer code such as
        ``configure(o, MODE_SAFE)`` refers to enum constants by name)."""
        if name in self.ctx_vars:
            return True
        if self.enum_consts is None:
            self.enum_consts = {
                v["field_name"]
                for e in self.target_library.get("enums", [])
                for v in e.get("enum_values", [])
            }
        return name in self.enum_consts

    def _find_context_function(self, ctx_call):
        """Resolve a consumer-context call to its definition in the analysis DB.

        The consumer JSON carries only the plain name (its "qname" field is
        filled with the name as well), so overloads are told apart by arity.
        A candidate needs at least as many recorded arguments as declared
        parameters, otherwise argument lookup would run past the end.

        Args:
            ctx_call (dict): the "call" part of a context entry.

        Returns:
            dict | None: matching function, or None if nothing fits.
        """
        name = ctx_call.get("name")
        n_args = len(ctx_call.get("args", []))
        by_name = [f for f in self.target_library["functions"] if f["name"] == name]
        exact = [f for f in by_name if len(f["params"]) == n_args]
        candidates = exact or [f for f in by_name if len(f["params"]) <= n_args]
        if not candidates:
            return None
        qname = ctx_call.get("qname")
        by_qname = [f for f in candidates if f.get("qname") == qname]
        if by_qname:
            candidates = by_qname
        if len(candidates) > 1:
            logger.warning(
                "Ambiguous definition for %s with %d args: %d candidates, using %s",
                name, n_args, len(candidates), candidates[0].get("qname"))
        return candidates[0]

    # ------------------------------------------------------------------ #
    #  Generate a context wrapper (writes the fuzz target file)           #
    # ------------------------------------------------------------------ #

    def _gen_context_wrapper(self, func):
        """Write a complete fuzz target file for a context-based call sequence.

        Args:
            func (dict): the last function definition in the context sequence,
                used for header/location information.

        Returns:
            bool: False if generation failed.
        """
        if not self.gen_anonymous and "(anonymous namespace)" in func["qname"]:
            self.state.curr_func_log = f"This function is in anonymous namespace!"
            self.state.gen_this_function = False
        found_parent = None
        if func["func_type"] in [FUNC_CXXMETHOD, FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR]:
            # Find parent class
            for r in self.target_library["records"]:
                if r["hash"] == func["parent_hash"]:
                    found_parent = r
                    break
            if not found_parent:
                self.state.gen_this_function = False

        # If there is no buffer - return!
        if (not len(self.state.buffer_size) and not self.state.dyn_cstring_size_idx and not self.state.dyn_cxxstring_size_idx and not self.state.dyn_wstring_size_idx and not self.state.file_idx) or not self.state.gen_this_function:
            log = self._log_file(func, self.gen_anonymous)
            if not log:
                logger.error(f"{CANNOT_CREATE_LOG_FILE} {func['qname']}")
            else:
                self.state.curr_func_log = f"Log for function: {func['qname']}\n{self.state.curr_func_log}"
                log.write(self.state.curr_func_log)
                log.close()
            return False
        # generate file name
        wrapper_result = self._wrapper_file(func)
        logger.info("Generating fuzzing-wapper for function %s:", func["qname"])
        logger.info("-- %s", wrapper_result["msg"])
        if not wrapper_result["file"]:
            self.state.gen_this_function = False
            return False
        f = wrapper_result["file"]
        for line in self._gen_header(func["location"]["fullpath"]):
            f.write(line)
        f.write('\n')
        compiler_info = self._get_compile_command(
            func["location"]["fullpath"])

        if self.target_type == LIBFUZZER:
            f.write(LIBFUZZER_PREFIX)
        else:
            f.write(AFLPLUSPLUS_PREFIX)

        buffer_check = str(self.state.dyn_wstring_size_idx) + "*sizeof(wchar_t) + " + str(self.state.dyn_cxxstring_size_idx) + \
            "*sizeof(char) + " + str(self.state.dyn_cstring_size_idx) + \
            " + " + str(self.state.file_idx)
        if self.state.buffer_size:
            buffer_check += " + " + " + ".join(self.state.buffer_size)
        f.write("    if (Fuzz_Size < " + buffer_check + ") return 0;\n")

        if self.state.dyn_cstring_size_idx > 0:
            f.write(
                "    size_t dyn_cstring_buffer = (size_t) ((Fuzz_Size + sizeof(char) - (" + buffer_check + " )));\n")
            f.write("    //generate random array of dynamic string sizes\n")
            f.write("    size_t dyn_cstring_size[" +
                    str(self.state.dyn_cstring_size_idx) + "];\n")
            if self.state.dyn_cstring_size_idx > 1:
                f.write("    srand(time(NULL));\n")
                f.write(
                    "    if(dyn_cstring_buffer == 0) dyn_cstring_size[0] = dyn_cstring_buffer; \n")
                f.write(
                    "    else dyn_cstring_size[0] = rand() % dyn_cstring_buffer; \n")
                f.write("    size_t remain = dyn_cstring_size[0];\n")
                f.write("    for(size_t i = 1; i< " +
                        str(self.state.dyn_cstring_size_idx) + " - 1; i++){\n")
                f.write(
                    "        if(dyn_cstring_buffer - remain == 0) dyn_cstring_size[i] = dyn_cstring_buffer - remain;\n")
                f.write(
                    "        else dyn_cstring_size[i] = rand() % (dyn_cstring_buffer - remain);\n")
                f.write("        remain += dyn_cstring_size[i];\n")
                f.write("    }\n")
                f.write(
                    "    dyn_cstring_size[" + str(self.state.dyn_cstring_size_idx) + " - 1] = dyn_cstring_buffer - remain;\n")
            else:
                f.write("    dyn_cstring_size[0] = dyn_cstring_buffer;\n")
            f.write(
                "    //end of generation random array of dynamic string sizes\n")

        if self.state.dyn_wstring_size_idx > 0:
            f.write("    size_t dyn_wstring_buffer = (size_t) ((Fuzz_Size + sizeof(wchar_t) - (" +
                    buffer_check + " )))/sizeof(wchar_t);\n")
            f.write("    //generate random array of dynamic string sizes\n")
            f.write("    size_t dyn_wstring_size[" +
                    str(self.state.dyn_wstring_size_idx) + "];\n")
            if self.state.dyn_wstring_size_idx > 1:
                f.write("    srand(time(NULL));\n")
                f.write(
                    "    if(dyn_wstring_buffer == 0) dyn_wstring_size[0] = dyn_wstring_buffer; \n")
                f.write(
                    "    else dyn_wstring_size[0] = rand() % dyn_wstring_buffer; \n")
                f.write("    size_t remain = dyn_wstring_size[0];\n")
                f.write("    for(size_t i = 1; i< " +
                        str(self.state.dyn_wstring_size_idx) + " - 1; i++){\n")
                f.write(
                    "        if(dyn_wstring_buffer - remain == 0) dyn_wstring_size[i] = dyn_wstring_buffer - remain;\n")
                f.write(
                    "        else dyn_wstring_size[i] = rand() % (dyn_wstring_buffer - remain);\n")
                f.write("        remain += dyn_wstring_size[i];\n")
                f.write("    }\n")
                f.write(
                    "    dyn_wstring_size[" + str(self.state.dyn_wstring_size_idx) + " - 1] = dyn_wstring_buffer - remain;\n")
            else:
                f.write("    dyn_wstring_size[0] = dyn_wstring_buffer;\n")
            f.write(
                "    //end of generation random array of dynamic string sizes\n")

        if self.state.dyn_cxxstring_size_idx > 0:
            f.write(
                "    size_t dyn_cxxstring_buffer = (size_t) ((Fuzz_Size + sizeof(char) - (" + buffer_check + " )));\n")
            f.write("    //generate random array of dynamic string sizes\n")
            f.write("    size_t dyn_cxxstring_size[" +
                    str(self.state.dyn_cxxstring_size_idx) + "];\n")
            if self.state.dyn_cxxstring_size_idx > 1:
                f.write("    srand(time(NULL));\n")
                f.write(
                    "    if(dyn_cxxstring_buffer == 0) dyn_cxxstring_size[0] = dyn_cxxstring_buffer; \n")
                f.write(
                    "    else dyn_cxxstring_size[0] = rand() % dyn_cxxstring_buffer; \n")
                f.write("    size_t remain = dyn_cxxstring_size[0];\n")
                f.write("    for(size_t i = 1; i< " +
                        str(self.state.dyn_cxxstring_size_idx) + " - 1; i++){\n")
                f.write(
                    "        if(dyn_cxxstring_buffer - remain == 0) dyn_cxxstring_size[i] = dyn_cxxstring_buffer - remain;\n")
                f.write(
                    "        else dyn_cxxstring_size[i] = rand() % (dyn_cxxstring_buffer - remain);\n")
                f.write("        remain += dyn_cxxstring_size[i];\n")
                f.write("    }\n")
                f.write(
                    "    dyn_cxxstring_size[" + str(self.state.dyn_cxxstring_size_idx) + " - 1] = dyn_cxxstring_buffer - remain;\n")
            else:
                f.write("    dyn_cxxstring_size[0] = dyn_cxxstring_buffer;\n")
            f.write(
                "    //end of generation random array of dynamic string sizes\n")

        if self.state.file_idx > 0:
            f.write("    size_t file_buffer = (size_t) ((Fuzz_Size + " +
                    str(self.state.file_idx) + " - (" + buffer_check + " )));\n")
            f.write("    //generate random array of dynamic file sizes\n")
            f.write("    size_t file_size[" +
                    str(self.state.file_idx) + "];\n")
            if self.state.file_idx > 1:
                f.write("    srand(time(NULL));\n")
                f.write(
                    "    if(file_buffer == 0) file_size[0] = file_buffer;\n")
                f.write("    else file_size[0] = rand() % file_buffer;\n")
                f.write("    size_t remain = file_size[0];\n")
                f.write("    for(size_t i = 1; i< " +
                        str(self.state.file_idx) + " - 1; i++){\n")
                f.write(
                    "        if(file_buffer - remain == 0) file_size[i] = file_buffer - remain;\n")
                f.write(
                    "        else file_size[i] = rand() % (file_buffer - remain);\n")
                f.write("        remain += file_size[i];\n")
                f.write("    }\n")
                f.write(
                    "    file_size[" + str(self.state.file_idx) + " - 1] = file_buffer - remain;\n")
            else:
                f.write("    file_size[0] = file_buffer;\n")
            f.write(
                "    //end of generation random array of dynamic file sizes\n")

        f.write("    uint8_t * futag_pos = Fuzz_Data;\n")
        if self.harness_preamble:
            f.write(self.harness_preamble)

        for line in self.state.gen_lines:
            f.write("    " + line)
        if self.target_type == LIBFUZZER:
            f.write(LIBFUZZER_SUFFIX)
        else:
            f.write(AFLPLUSPLUS_SUFFIX)
        f.close()
        return True

    # ------------------------------------------------------------------ #
    #  Public API: generate context-aware fuzz targets                    #
    # ------------------------------------------------------------------ #

    def gen_context(self, max_wrappers: int = 10):
        """Generate fuzz targets from consumer usage contexts.

        Args:
            max_wrappers (int): maximum number of wrapper variants per function.
        """
        self.max_wrappers = max_wrappers
        self.sort_callexprs()
        if not self.total_context:
            sys.exit("-- [Futag] empty context, exited!")

        # Every context ends in exactly one bucket; the sum equals "total".
        self.context_stats = {
            "total": len(self.total_context),
            "generated": 0,
            "missing_definition": 0,
            "empty": 0,
            "rejected": 0,
        }
        self.unbound_args = 0
        for curr_context in self.total_context:
            self.state.gen_this_function = True
            self.state.header = []
            self.state.buffer_size = []
            self.state.gen_lines = []
            self.state.gen_free = []
            self.state.dyn_cstring_size_idx = 0
            self.state.dyn_wstring_size_idx = 0
            self.state.dyn_cxxstring_size_idx = 0
            self.state.file_idx = 0
            self.state.var_function_idx = 0
            self.var_idx = 0
            self.state.param_list = []
            self.state.curr_func_log = ""

            # A wrapper that silently drops one call of the sequence
            # reproduces a different scenario, so an unresolved call
            # discards the whole context instead of being skipped.
            self.ctx_vars = {item["var"] for item in curr_context if item["var"]}
            target_func = None
            missing = None
            for call in curr_context:
                func = self._find_context_function(call["call"])
                if func is None:
                    missing = call["call"].get("name")
                    break
                target_func = func
                self._gen_context_target_function(call, func, 0)

            if missing is not None:
                logger.warning(
                    "Context skipped: no definition for %s (%d args) in analysis result",
                    missing, len(call["call"].get("args", [])))
                self.context_stats["missing_definition"] += 1
                continue
            if target_func is None:
                self.context_stats["empty"] += 1
                continue
            if self._gen_context_wrapper(target_func):
                self.context_stats["generated"] += 1
            else:
                self.context_stats["rejected"] += 1
        logger.info("Context generation summary: %s, unbound VARREF args fuzzed: %d",
                    self.context_stats, self.unbound_args)
