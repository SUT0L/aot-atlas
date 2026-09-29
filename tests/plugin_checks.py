import argparse
import ctypes
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path

import binaryninja as bn


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACTS = ROOT / "artifacts"
PROPERTY_PROJECT = ROOT / "tests/PropertyDispatchProbe/PropertyDispatchProbe.csproj"
DICTIONARY_PROJECT = ROOT / "tests/DictionaryProbe/DictionaryProbe.csproj"
TRACE_PROJECT = ROOT / "tests/TraceAbiProbe/TraceAbiProbe.csproj"


class ApplyStats(ctypes.Structure):
    _fields_ = [
        ("input_bytes", ctypes.c_uint64),
        ("image_base", ctypes.c_uint64),
        ("method_tables", ctypes.c_uint32),
        ("data_variables", ctypes.c_uint32),
        ("symbols", ctypes.c_uint32),
        ("data_references", ctypes.c_uint32),
        ("extract_seconds", ctypes.c_double),
        ("apply_seconds", ctypes.c_double),
        ("input_sha256", ctypes.c_ubyte * 32),
    ]


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run(command):
    process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip()
        raise RuntimeError(f"{' '.join(map(str, command))}\n{detail}")
    return process.stdout.strip()


def publish(project, output, framework=None):
    command = [
        "dotnet",
        "publish",
        str(project),
        "-c",
        "Release",
        "-r",
        "win-x64",
        "-o",
        str(output),
    ]
    if framework is not None:
        command.append(f"-p:ProbeFramework={framework}")
    run(command)


def prepare_artifacts(artifacts, framework):
    runtime = framework.removeprefix("net").split(".", 1)[0]
    cli_directory = artifacts / "native"
    plugin_directory = artifacts / "binja-native"
    property_directory = artifacts / f"property-dispatch-net{runtime}"
    dictionary_directory = artifacts / f"dictionary-probe-net{runtime}"
    trace_directory = artifacts / f"trace-abi-net{runtime}"

    publish(ROOT / "src/Atlas.Cli/Atlas.Cli.csproj", cli_directory)
    publish(ROOT / "src/Atlas.Binja/Atlas.Binja.csproj", plugin_directory)
    publish(PROPERTY_PROJECT, property_directory, framework)
    publish(DICTIONARY_PROJECT, dictionary_directory, framework)
    publish(TRACE_PROJECT, trace_directory, framework)

    return {
        "cli": cli_directory / "aot-atlas.exe",
        "plugin": plugin_directory / "aot-atlas-binja.dll",
        "property": property_directory / "PropertyDispatchProbe.exe",
        "dictionary": dictionary_directory / "DictionaryProbe.exe",
        "trace": trace_directory / "TraceAbiProbe.exe",
    }


def extract(cli, binary, directory):
    output = directory / f"{binary.stem}.json"
    run([str(cli), "extract", str(binary), str(output)])
    result = json.loads(output.read_text(encoding="utf-8"))
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    require(result["operation"] == "extract", f"{binary.name}: wrong extraction operation")
    require(result["input_sha256"] == digest, f"{binary.name}: extraction input hash mismatch")
    return result


class Plugin:
    def __init__(self, path):
        self.path = path
        self.digest = hashlib.sha256(path.read_bytes()).hexdigest()
        self.library = ctypes.CDLL(str(path))
        self.library.CorePluginABIVersion.restype = ctypes.c_uint32
        self.library.CorePluginInit.restype = ctypes.c_uint8
        self.library.AtlasApplyMetadata.argtypes = [ctypes.c_void_p, ctypes.c_uint8, ctypes.POINTER(ApplyStats)]
        self.library.AtlasApplyMetadata.restype = ctypes.c_int
        self.library.AtlasApplyFieldReferences.argtypes = [ctypes.c_void_p]
        self.library.AtlasApplyFieldReferences.restype = ctypes.c_int

        require(self.library.CorePluginABIVersion() == 187, "plugin exposes the wrong Binary Ninja ABI")
        require(self.library.CorePluginInit() == 1, "plugin initialization failed")
        require(any(command.name == "AOT Atlas\\Apply metadata" for command in bn.PluginCommand),
                "plugin command was not registered")

    def apply(self, view, expected_status=0):
        stats = ApplyStats()
        status = self.library.AtlasApplyMetadata(
            ctypes.cast(view.handle, ctypes.c_void_p), 0, ctypes.byref(stats))
        require(status == expected_status, f"metadata apply returned {status}, expected {expected_status}")
        return stats


def preferred_image_base(binary):
    data = binary.read_bytes()
    pe_offset = struct.unpack_from("<I", data, 60)[0]
    return struct.unpack_from("<Q", data, pe_offset + 48)[0]


def property_member_name(projection):
    prefixes = {
        "Direct": "property",
        "Canonical": "canonical_property",
        "Interface": "interface_property",
        "Base": "base_property",
    }
    prefix = prefixes[projection["origin"]]
    if projection["getter"] == 0:
        prefix += "_store"
    name = prefix + "::"
    if projection["owner"] != projection["contract"]:
        name += projection["contract_name"] + "::"
    return name + projection["property_name"]


def property_function_name(projection, accessor):
    prefixes = {
        "Direct": "property",
        "Canonical": "canonical_property",
        "Interface": "interface_property",
        "Base": "base_property",
    }
    suffix = "set" if accessor["setter"] else "get"
    return (f"{prefixes[projection['origin']]}::{projection['owner_name']}::"
            f"{projection['contract_name']}::{projection['property_name']}::{suffix}")


def property_tag(view, address):
    matches = [tag for tag in view.get_tags_at(address, auto=False)
               if tag.type.name == "AOT Atlas properties"]
    require(len(matches) >= 1, f"0x{address:X}: missing property tag")
    return matches


def verify_property_projection(view, extraction, image_base, delta):
    expected = extraction["properties"]
    projections_by_owner = {}
    for projection in expected["projections"]:
        projections_by_owner.setdefault(projection["owner"], []).append(projection)

    require(projections_by_owner, "property fixture produced no projections")
    for owner, projections in projections_by_owner.items():
        rva = owner - image_base
        runtime_id = f"aot-atlas:runtime-type:v1:{rva:08X}"
        property_id = f"aot-atlas:property-view:v1:{rva:08X}"
        runtime_type = view.get_type_by_id(runtime_id)
        property_type = view.get_type_by_id(property_id)
        require(runtime_type is not None, f"{runtime_id}: missing runtime type")
        require(property_type is not None, f"{property_id}: missing property view")
        require(property_type.type_class == bn.TypeClass.StructureTypeClass and property_type.packed,
                f"{property_id}: property view is not a packed structure")
        require(property_type.width == runtime_type.width,
                f"{property_id}: property view changed the runtime width")

        expected_members = sorted(
            (property_member_name(item), item["offset"], item["size"])
            for item in projections)
        actual_members = sorted(
            (member.name, member.offset, member.type.width)
            for member in property_type.members)
        require(actual_members == expected_members, f"{property_id}: projected members differ")
        property_tag(view, owner + delta)

        method_table = view.get_data_var_at(owner + delta)
        require(method_table is not None and method_table.type.width == 24,
                f"0x{owner + delta:X}: missing MethodTable data variable")
        names = {symbol.full_name for symbol in view.get_symbols(owner + delta, 1)}
        require(f"methodtable::{projections[0]['owner_name']}" in names,
                f"0x{owner + delta:X}: missing MethodTable symbol")

    for accessor in expected["accessor_functions"]:
        address = accessor["address"] + delta
        function = view.get_function_at(address)
        require(function is not None, f"0x{address:X}: missing property accessor function")
        require(function.type.calling_convention.name == "win64",
                f"0x{address:X}: property accessor has the wrong calling convention")

    return projections_by_owner, expected["accessor_functions"]


def verify_property_accessor_symbols(view, extraction, delta):
    expected = extraction["properties"]
    for accessor in expected["accessor_functions"]:
        projection = expected["projections"][accessor["projection"]]
        address = accessor["address"] + delta
        symbols = {symbol.full_name for symbol in view.get_symbols(address, 1)}
        trace_names = {entry["name"] for entry in extraction["methods"]["stack_trace"]
                       if not entry["hidden"] and entry["entrypoint"] == accessor["address"]}
        expected_name = property_function_name(projection, accessor)
        require(expected_name in symbols or symbols & trace_names,
                f"0x{address:X}: missing property accessor symbol")


def check_property_workflow(plugin, binary, extraction, temporary_directory):
    image_base = preferred_image_base(binary)
    database = temporary_directory / "property-check.bndb"
    with bn.load(str(binary), update_analysis=False) as view:
        view.set_analysis_hold(True)
        try:
            stats = plugin.apply(view)
        finally:
            view.set_analysis_hold(False)
        view.update_analysis_and_wait()

        require(bytes(stats.input_sha256).hex() == extraction["input_sha256"],
                "plugin stats contain the wrong input hash")
        require(stats.method_tables == len(extraction["types"]["types"]),
                "plugin stats contain the wrong MethodTable count")
        owners, accessors = verify_property_projection(
            view, extraction, image_base, view.start - image_base)
        verify_property_accessor_symbols(view, extraction, view.start - image_base)

        # The first analysis can discover import symbols after Atlas has applied its annotations
        # A second application reconciles those stronger host symbols
        plugin.apply(view)
        view.update_analysis_and_wait()
        verify_property_projection(view, extraction, image_base, view.start - image_base)
        verify_property_accessor_symbols(view, extraction, view.start - image_base)

        accessor = accessors[0]
        address = accessor["address"] + view.start - image_base
        function = view.get_function_at(address)
        function.name = "atlas_fixture_user_property"
        function.user_type = bn.Type.function(
            bn.Type.int(2, False),
            [bn.FunctionParameter(bn.Type.int(1, False), "user_value")])
        user_type = str(function.type)

        owner_address = next(iter(owners)) + view.start - image_base
        view.add_tag(owner_address, "AOT Atlas properties", "atlas fixture user tag", user=True)
        user_tags = [tag.id for tag in property_tag(view, owner_address)
                     if tag.data == "atlas fixture user tag"]
        require(len(user_tags) == 1, "failed to create the user-owned property tag")

        symbols_before = {
            (symbol.address, symbol.full_name, symbol.short_name)
            for symbol in view.get_symbols() if not symbol.auto}
        plugin.apply(view)
        view.update_analysis_and_wait()
        verify_property_projection(view, extraction, image_base, view.start - image_base)
        require(view.get_function_at(address).name == "atlas_fixture_user_property",
                "repeat apply replaced the user function name")
        require(str(view.get_function_at(address).type) == user_type,
                "repeat apply replaced the user function type")
        require(any(tag.id == user_tags[0] for tag in property_tag(view, owner_address)),
                "repeat apply removed the user property tag")
        symbols_after = {
            (symbol.address, symbol.full_name, symbol.short_name)
            for symbol in view.get_symbols() if not symbol.auto}
        removed_symbols = sorted(symbols_before - symbols_after)
        added_symbols = sorted(symbols_after - symbols_before)
        require(
            not removed_symbols and not added_symbols,
            f"repeat apply changed user-visible symbols; "
            f"removed={removed_symbols[:3]!r}, added={added_symbols[:3]!r}")

        stamp = view.query_metadata("aot-atlas:apply-input")
        invalid_stamp = bytearray(stamp)
        invalid_stamp[8] ^= 1
        view.store_metadata("aot-atlas:apply-input", bytes(invalid_stamp))
        plugin.apply(view, expected_status=1)
        require(view.get_function_at(address).name == "atlas_fixture_user_property",
                "rejected input changed the user function")
        view.store_metadata("aot-atlas:apply-input", stamp)
        plugin.apply(view)

        require(view.create_database(str(database)), "failed to save the Binary Ninja database")

    with bn.load(str(database), update_analysis=False) as restored:
        restored.update_analysis_and_wait()
        verify_property_projection(restored, extraction, image_base, restored.start - image_base)
        require(restored.get_function_at(address).name == "atlas_fixture_user_property",
                "saved database lost the user function name")
        require(str(restored.get_function_at(address).type) == user_type,
                "saved database lost the user function type")
        require(any(tag.id == user_tags[0] for tag in property_tag(restored, owner_address)),
                "saved database lost the user property tag")

    rebased_start = 0x150000000
    with bn.load(str(binary), update_analysis=False, options={"loader.imageBase": rebased_start}) as rebased:
        rebased.set_analysis_hold(True)
        try:
            plugin.apply(rebased)
        finally:
            rebased.set_analysis_hold(False)
        rebased.update_analysis_and_wait()
        verify_property_projection(rebased, extraction, image_base, rebased.start - image_base)
        verify_property_accessor_symbols(rebased, extraction, rebased.start - image_base)

    return {
        "property_views": len(owners),
        "property_accessors": len(accessors),
        "repeat_stable": True,
        "user_annotations_preserved": True,
        "rejected_input_preserved_state": True,
        "database_restored": True,
        "rebase_verified": True,
    }


def dictionary_tag_text(instance, slot, recipe):
    kind = recipe["kind_name"]
    if kind == "MethodDictionary":
        identity = slot["target_method_name"]
    else:
        identity = slot["type_name"]
        if kind == "StaticData":
            kind = "GcStaticCell" if recipe["storage"] == "gc_cell" else "NonGcStaticBase"
        elif kind == "InterfaceCall":
            identity += f"::slot_{slot['interface_slot']}"
    return f"native_layout::{recipe['offset']:08X}::{kind}::{identity}"


def check_dictionary_workflow(plugin, binary, extraction):
    image_base = preferred_image_base(binary)
    recipes = extraction["dictionaries"]["recipes"]
    samples = {}
    for instance in extraction["dictionaries"]["instances"]:
        for slot in instance["slots"]:
            if slot["status"] != "Verified":
                continue
            recipe = recipes[slot["recipe"]]
            samples.setdefault(recipe["kind_name"], (instance, slot, recipe))

    required_kinds = {"TypeHandle", "MethodDictionary", "StaticData", "InterfaceCall"}
    require(required_kinds <= samples.keys(), "dictionary fixture is missing a recovery kind")

    with bn.load(str(binary), update_analysis=False) as view:
        view.set_analysis_hold(True)
        try:
            plugin.apply(view)
        finally:
            view.set_analysis_hold(False)
        view.update_analysis_and_wait()
        delta = view.start - image_base

        for kind in sorted(required_kinds):
            instance, slot, recipe = samples[kind]
            address = slot["address"] + delta
            variable = view.get_data_var_at(address)
            require(variable is not None and variable.type.width == 8,
                    f"{kind}: missing dictionary slot data variable")
            tags = [tag.data for tag in view.get_tags_at(address, auto=False)
                    if tag.type.name == "AOT Atlas dictionaries"]
            require(dictionary_tag_text(instance, slot, recipe) in tags,
                    f"{kind}: missing dictionary relationship tag")
            references = set(view.get_data_refs_from(address))
            require(slot["value"] + delta in references,
                    f"{kind}: missing recovered value reference")
            require(slot["recipe_address"] + delta in references,
                    f"{kind}: missing NativeLayout recipe reference")
            require(instance["method_witness"] + delta in references,
                    f"{kind}: missing method witness reference")

        helpers = extraction["runtime_helpers"]
        require(helpers["status"] == "Complete", "runtime helper fixture did not resolve")
        table_address = helpers["classlib_table"] + delta
        table = view.get_data_var_at(table_address)
        require(table is not None and table.type.width == 8 * helpers["table_count"],
                "class-library helper table has the wrong type")
        members = {member.offset: member.name for member in table.type.members}
        for helper in helpers["helpers"]:
            offset = helper["cell"] - helpers["classlib_table"]
            require(members.get(offset) == helper["role"],
                    f"runtime helper cell +0x{offset:X} has the wrong role")
            require(view.get_function_at(helper["address"] + delta) is not None,
                    f"runtime helper {helper['role']} has no function")
            require(helper["address"] + delta in view.get_data_refs_from(helper["cell"] + delta),
                    f"runtime helper {helper['role']} has no cell reference")

        cells = extraction["dispatch_cells"]["cells"]
        require(cells, "dispatch-cell fixture produced no cells")
        cell = cells[0]
        cell_address = cell["address"] + delta
        variable = view.get_data_var_at(cell_address)
        require(variable is not None and variable.type.width == 16,
                "dispatch cell has no 16-byte data variable")
        members = [(member.name, member.offset, member.type.width) for member in variable.type.members]
        require(members == [("stub", 0, 8), ("cache_or_interface", 8, 8)],
                "dispatch cell has the wrong structure")
        names = {symbol.full_name for symbol in view.get_symbols(cell_address, 1)}
        expected_name = (f"dispatch_cell::{cell['interface_name']}::slot_{cell['slot']}::"
                         f"{cell['address'] - image_base:08X}")
        require(expected_name in names, "dispatch cell has the wrong symbol")
        require(cell["stub"] + delta in view.get_data_refs_from(cell_address),
                "dispatch cell has no stub reference")

    return {
        "dictionary_kinds": len(required_kinds),
        "runtime_helpers": len(helpers["helpers"]),
        "dispatch_cells": len(cells),
    }


def location_name(view, location, expected):
    require(location is not None and len(location.components) == 1,
            f"{expected}: value has no single physical location")
    component = location.components[0]
    if expected.startswith("stack+"):
        require(component.var.source_type == bn.VariableSourceType.StackVariableSourceType,
                f"{expected}: value is not on the stack")
        require(component.var.storage == int(expected[6:]),
                f"{expected}: value has the wrong stack offset")
        return expected

    require(component.var.source_type == bn.VariableSourceType.RegisterVariableSourceType,
            f"{expected}: value is not in a register")
    return view.arch.get_reg_name(component.var.storage)


def verify_trace_type(view, entry, delta):
    identifier = f"aot-atlas:trace-signature:v1:{entry['witness_rva']:08X}"
    signature = view.get_type_by_id(identifier)
    require(signature is not None and signature.type_class == bn.TypeClass.FunctionTypeClass,
            f"{identifier}: missing trace signature")
    require(signature.calling_convention.name == "win64", f"{identifier}: wrong calling convention")

    parameters = signature.parameters_with_all_locations
    expected_parameters = entry["abi"]["parameters"]
    require(len(parameters) == len(expected_parameters), f"{identifier}: wrong parameter count")
    function = view.get_function_at(entry["entrypoint"] + delta)
    result = bn.ReturnValue(signature.return_value, signature.return_value_location)
    result = view.deref_return_value_named_type_references(result)
    resolved_parameters = view.deref_parameter_named_type_references(parameters)
    layout = signature.calling_convention.get_call_layout(view, result, resolved_parameters, function)

    actual_types = [signature.return_value] + [parameter.type for parameter in parameters]
    actual_locations = [layout.return_value] + list(layout.parameters)
    expected_values = [entry["abi"]["return"]] + expected_parameters
    for actual_type, actual_location, expected_value in zip(actual_types, actual_locations, expected_values):
        require(actual_type.width == expected_value["size"],
                f"{identifier}: {expected_value['role'] if 'role' in expected_value else 'return'} width differs")
        if expected_value["kind"] == "void":
            require(actual_location is None, f"{identifier}: void result has a location")
            continue
        require(location_name(view, actual_location, expected_value["location"]) == expected_value["location"],
                f"{identifier}: physical location differs")
        require(actual_location.indirect == expected_value["indirect"],
                f"{identifier}: indirection differs")


def check_trace_workflow(plugin, binary, extraction, temporary_directory):
    image_base = preferred_image_base(binary)
    accepted_names = {
        ("TraceFunctions", "Signed"),
        ("TraceFunctions", "Mix"),
        ("TraceFunctions", "Large"),
        ("TraceFunctions", "ByRef"),
        ("TraceOwner", "Large"),
        ("TraceCounter", "Add"),
    }
    accepted = [entry for entry in extraction["methods"]["stack_trace"]
                if (entry["declaring_type"], entry["method_name"]) in accepted_names
                and entry["abi"]["status"] == "trace_identity"]
    require(len(accepted) == len(accepted_names), "trace fixture did not retain all six callable identities")

    with bn.load(str(binary), update_analysis=False) as view:
        view.set_analysis_hold(True)
        try:
            plugin.apply(view)
        finally:
            view.set_analysis_hold(False)
        view.update_analysis_and_wait()
        delta = view.start - image_base
        for entry in accepted:
            verify_trace_type(view, entry, delta)

    audit = []
    for entry in accepted:
        name = "OwnerLarge" if entry["declaring_type"] == "TraceOwner" else entry["method_name"]
        audit.append(f"{name}|{entry['entrypoint'] - image_base:X}")
    audit_path = temporary_directory / "trace-calls.txt"
    audit_path.write_text("\n".join(audit) + "\n", encoding="ascii")
    output = run([str(binary), str(audit_path)])
    output_lines = output.splitlines()
    require(output_lines, "trace entrypoint audit produced no output")
    result = output_lines[-1]
    require(
        result == "PASS: six trace entrypoints agree with direct managed calls.",
        f"trace entrypoint audit ended with {result!r}")

    return {"trace_signatures": len(accepted), "live_trace_calls": len(audit)}


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description="Build and run the AOT Atlas Binary Ninja integration checks.")
    parser.add_argument("--artifacts", type=Path, default=DEFAULT_ARTIFACTS)
    parser.add_argument("--framework", default="net10.0")
    parser.add_argument("--no-build", action="store_true")
    return parser.parse_args(argv)


def main(argv=None):
    arguments = parse_arguments(argv)
    artifacts = arguments.artifacts.resolve()
    if arguments.no_build:
        runtime = arguments.framework.removeprefix("net").split(".", 1)[0]
        paths = {
            "cli": artifacts / "native/aot-atlas.exe",
            "plugin": artifacts / "binja-native/aot-atlas-binja.dll",
            "property": artifacts / f"property-dispatch-net{runtime}/PropertyDispatchProbe.exe",
            "dictionary": artifacts / f"dictionary-probe-net{runtime}/DictionaryProbe.exe",
            "trace": artifacts / f"trace-abi-net{runtime}/TraceAbiProbe.exe",
        }
    else:
        paths = prepare_artifacts(artifacts, arguments.framework)

    for name, path in paths.items():
        require(path.is_file(), f"{name} artifact does not exist: {path}")

    plugin = Plugin(paths["plugin"])
    with tempfile.TemporaryDirectory(prefix="aot-atlas-plugin-checks-") as temporary:
        temporary_directory = Path(temporary)
        extractions = {
            name: extract(paths["cli"], paths[name], temporary_directory)
            for name in ("property", "dictionary", "trace")
        }
        result = {
            "plugin_sha256": plugin.digest,
            "binary_ninja": bn.core_version(),
            "property": check_property_workflow(
                plugin, paths["property"], extractions["property"], temporary_directory),
            "dictionary": check_dictionary_workflow(
                plugin, paths["dictionary"], extractions["dictionary"]),
            "trace": check_trace_workflow(
                plugin, paths["trace"], extractions["trace"], temporary_directory),
        }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
