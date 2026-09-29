import argparse
import ctypes
import hashlib
import json
import os
import struct
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run(command):
    process = subprocess.run(command, capture_output=True, text=True)
    if process.returncode != 0:
        raise RuntimeError(process.stderr.strip() or process.stdout.strip())
    return process.stdout


def image_base(data):
    pe_offset = struct.unpack_from("<I", data, 60)[0]
    return struct.unpack_from("<Q", data, pe_offset + 48)[0]


def extract(cli, operation, binary, output):
    run([str(cli), operation, str(binary), str(output)])
    result = json.loads(output.read_text(encoding="utf-8-sig"))
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    require(result["input_sha256"] == digest, f"{binary.name}: extraction hash differs")
    return result


def check_enums(arguments):
    expected = json.loads(arguments.runtime.read_text(encoding="utf-8-sig"))
    actual = json.loads(arguments.extraction.read_text(encoding="utf-8-sig"))
    require(expected["input_sha256"] == actual["input_sha256"], "enum inputs differ")
    definitions = {entry["metadata_type"]: entry for entry in actual["definitions"]}
    runtime_types = {entry["address"] - actual["image_base"]: entry for entry in actual["runtime_types"]}

    for entry in expected["types"]:
        definition = definitions[runtime_types[entry["rva"]]["metadata_type"]]
        for key in ("width", "signed", "flags"):
            require(entry[key] == definition[key], f"{entry['name']}: enum {key} differs")
        members = {member["name"]: member["bits"] for member in definition["members"]}
        require(members == entry["members"], f"{entry['name']}: enum members differ")

    require({entry["width"] for entry in expected["types"]} == {1, 2, 4, 8},
            "enum fixture does not cover every storage width")
    require(len(expected["types"]) == 12, "enum fixture does not contain twelve live types")
    print("enums: 12 live types match widths, signedness, flags, names, and value bits")


def check_linkage(arguments):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
    kernel.LoadLibraryW.restype = ctypes.c_void_p
    kernel.FreeLibrary.argtypes = [ctypes.c_void_p]
    kernel.FreeLibrary.restype = ctypes.c_int
    kernel.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    kernel.GetProcAddress.restype = ctypes.c_void_p
    golden = json.loads((ROOT / "tests/golden/PeLinkageProbe.json").read_text())

    folder = arguments.folder.resolve()
    with os.add_dll_directory(str(folder)):
        provider = ctypes.WinDLL(str(folder / "AtlasLinkageProvider.dll"))
        consumer = ctypes.WinDLL(str(folder / "AtlasLinkageConsumer.dll"))
        consumer.Run.argtypes = [ctypes.c_int]
        consumer.Run.restype = ctypes.c_int
        require(consumer.Run(7) == 33, "linkage consumer returned the wrong result")

        for library in (provider, consumer):
            binary = Path(library._name)
            output = binary.with_suffix(".linkage.json")
            actual = extract(arguments.executable, "linkage", binary, output)
            base = actual["image_base"]
            matched = 0
            for module in actual["import_modules"]:
                handle = kernel.LoadLibraryW(module["module"])
                require(handle, f"failed to load import module {module['module']}")
                try:
                    for entry in module["imports"]:
                        name = entry["import_name"].encode("ascii") if entry["kind"] == "Name" else entry["ordinal"]
                        symbol = ctypes.cast(ctypes.c_char_p(name), ctypes.c_void_p) if isinstance(name, bytes) else name
                        target = kernel.GetProcAddress(handle, symbol)
                        cell = library._handle + entry["address_cell"] - base
                        require(target and ctypes.c_void_p.from_address(cell).value == target,
                                f"{binary.name}: live IAT target differs")
                        matched += 1
                finally:
                    require(kernel.FreeLibrary(handle), f"failed to release {module['module']}")

            for entry in actual["exports"]:
                cell = library._handle + entry["address_cell"] - base
                require(ctypes.c_uint32.from_address(cell).value == entry["rva"],
                        f"{binary.name}: live export cell differs")
                if entry["kind"] == "Unused":
                    require(entry["rva"] == entry["address"] == 0,
                            f"{binary.name}: unused export has an address")
                    continue
                target = kernel.GetProcAddress(library._handle, entry["ordinal"])
                require(target, f"{binary.name}: exported ordinal is not loadable")
                if entry["kind"] == "Forwarder":
                    require(entry["address"] == 0 and entry["forwarder"] == "KERNEL32.GetCurrentProcessId",
                            f"{binary.name}: forwarded export differs")
                    require(ctypes.WINFUNCTYPE(ctypes.c_uint32)(target)() == os.getpid(),
                            f"{binary.name}: forwarded export called the wrong target")
                else:
                    require(target == library._handle + entry["address"] - base,
                            f"{binary.name}: exported address differs from the loader")
                for alias in entry["aliases"]:
                    name = ctypes.cast(ctypes.c_char_p(alias["export_name"].encode("ascii")), ctypes.c_void_p)
                    require(kernel.GetProcAddress(library._handle, name) == target,
                            f"{binary.name}: export alias differs")

            if library is provider:
                normalized = [
                    {
                        "ordinal": entry["ordinal"],
                        "kind": entry["kind"],
                        "aliases": [alias["export_name"] for alias in entry["aliases"]],
                    }
                    for entry in actual["exports"]
                ]
                require(normalized == golden["provider_exports"], "provider exports differ from the fixture contract")
                value_name = ctypes.cast(ctypes.c_char_p(b"Value"), ctypes.c_void_p)
                value = kernel.GetProcAddress(provider._handle, value_name)
                require(ctypes.c_int.from_address(value).value == 0x12345678,
                        "provider data export has the wrong live value")
                ordinal = kernel.GetProcAddress(provider._handle, 7)
                require(ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)(ordinal)(9) == 27,
                        "provider ordinal export called the wrong function")
            else:
                selected = [
                    {
                        "module": module["module"],
                        "delay_loaded": module["delay_loaded"],
                        "imports": [entry.get("import_name", f"#{entry.get('ordinal')}") for entry in module["imports"]],
                    }
                    for module in actual["import_modules"]
                    if module["module"].lower() in ("atlaslinkageprovider.dll", "user32.dll")
                ]
                require(selected == golden["consumer_imports"], "consumer imports differ from the fixture contract")
            print(f"linkage: {binary.name}, {matched} live IAT targets and {len(actual['exports'])} export slots")


MANAGED_LAYOUTS = {
    "Functions::Mix": ("float", 8, "xmm0", False, [
        ("integer", 4, "rcx", False), ("float", 4, "xmm1", False),
        ("integer", 8, "r8", False), ("float", 8, "xmm3", False),
        ("integer", 4, "stack+40", False),
    ]),
    "Functions::Small": ("value", 8, "rax", False, [("value", 8, "rcx", False)]),
    "Functions::FloatStruct": ("value", 4, "rax", False, [("value", 4, "rcx", False)]),
    "Functions::Packed": ("value", 5, "rcx", True, [("value", 5, "rdx", True)]),
    "Functions::Large": ("value", 24, "rcx", True, [("value", 24, "rdx", True)]),
    "Functions::Vector128": ("value", 16, "rcx", True, [("value", 16, "rdx", True)]),
    "Functions::Vector256": ("value", 32, "rcx", True, [("value", 32, "rdx", True)]),
    "Functions::Generic": ("value", 24, "rcx", True, [
        ("context", 8, "rdx", False), ("reference", 8, "r8", False),
        ("integer", 8, "r9", False),
    ]),
    "Functions::Reference": ("integer", 4, "rax", False, [("byref", 8, "rcx", False)]),
    "Functions::Pointer": ("integer", 4, "rax", False, [("pointer", 8, "rcx", False)]),
    "Functions::Signed": ("integer", 1, "rax", False, [("integer", 1, "rcx", False)]),
    "Owner::Mix": ("float", 8, "xmm0", False, [
        ("reference", 8, "rcx", False), ("float", 4, "xmm1", False),
        ("integer", 8, "r8", False), ("float", 8, "xmm3", False),
        ("integer", 4, "stack+40", False),
    ]),
    "Owner::Large": ("value", 24, "rdx", True, [
        ("reference", 8, "rcx", False), ("integer", 4, "r8", False),
    ]),
    "Owner::Generic": ("value", 24, "rdx", True, [
        ("reference", 8, "rcx", False), ("context", 8, "r8", False),
        ("reference", 8, "r9", False), ("integer", 8, "stack+40", False),
    ]),
    "Counter::Add": ("integer", 4, "rax", False, [
        ("boxed_reference", 8, "rcx", False), ("integer", 4, "rdx", False),
    ]),
}


def check_managed_abi(arguments):
    with tempfile.TemporaryDirectory(prefix="aot-atlas-managed-abi-") as temporary:
        directory = Path(temporary)
        for binary in arguments.binaries:
            binary = binary.resolve()
            base = image_base(binary.read_bytes())
            output = directory / f"{binary.stem}.json"
            expected = extract(arguments.executable, "methods", binary, output)
            lines = run([str(binary)]).splitlines()
            require(len(lines) == 15, f"{binary.name}: expected fifteen runtime method identities")
            audit = []
            for line in lines:
                name, owner_rva, argument_rva = line.split("|")
                owner = base + int(owner_rva, 16)
                type_arguments = [base + int(argument_rva, 16)] if argument_rva else []
                matches = [entry for entry in expected["methods"]
                           if entry["declaring_type"] == owner and entry["method_name"] == name
                           and entry["arguments"] == type_arguments]
                require(len(matches) == 1, f"{binary.name}: {line} has no unique extracted method")
                entry = matches[0]
                dictionary = entry["dictionary"]
                if dictionary:
                    identity = "metadata_offset" if entry["metadata_offset"] else "native_offset"
                    matches = [candidate for candidate in expected["methods"]
                               if candidate["declaring_type"] == owner
                               and candidate[identity] == entry[identity]
                               and candidate["section"] == 306 and candidate["flags"] & 16]
                    require(len(matches) == 1, f"{binary.name}: {line} has no unique callable body")
                    entry = matches[0]

                abi = entry["abi"]
                require(entry["entrypoint"] and not entry["async_variant"] and abi["status"] == "complete",
                        f"{binary.name}: {entry['name']} has no complete ABI")
                layout = MANAGED_LAYOUTS[entry["name"].split("<")[0]]
                result = abi["return"]
                actual_result = tuple(result[key] for key in ("kind", "size", "location", "indirect"))
                require(actual_result == layout[:4], f"{binary.name}: {entry['name']} return ABI differs")
                actual_parameters = [
                    tuple(parameter[key] for key in ("kind", "size", "location", "indirect"))
                    for parameter in abi["parameters"]
                ]
                require(actual_parameters == layout[4], f"{binary.name}: {entry['name']} parameter ABI differs")
                require(result.get("returned_pointer") == ("rax" if result["indirect"] else None),
                        f"{binary.name}: {entry['name']} returned-pointer ABI differs")
                expected_receiver = not entry["name"].startswith("Functions::")
                actual_receivers = sum(parameter["role"] == "this" for parameter in abi["parameters"])
                require(actual_receivers == expected_receiver,
                        f"{binary.name}: {entry['name']} receiver ABI differs")
                actual_contexts = sum(parameter["role"] == "generic_context" for parameter in abi["parameters"])
                require(actual_contexts == bool(dictionary),
                        f"{binary.name}: {entry['name']} generic-context ABI differs")
                audit.append(f"{name}|{owner_rva}|{entry['entrypoint'] - base:X}|{dictionary - base if dictionary else 0:X}")

            audit_path = directory / f"{binary.stem}.calls.txt"
            audit_path.write_text("\n".join(audit) + "\n", encoding="ascii")
            runtime = run([str(binary), str(audit_path)]).strip()
            require(runtime == "15 metadata entrypoints agree with direct managed calls.",
                    f"{binary.name}: callable ABI disagrees with managed calls")
            print(f"managed ABI: {binary.parent.name}, 15 live calls")


def check_method_signatures(arguments):
    with tempfile.TemporaryDirectory(prefix="aot-atlas-method-signatures-") as temporary:
        directory = Path(temporary)
        for binary in arguments.binaries:
            binary = binary.resolve()
            base = image_base(binary.read_bytes())
            expected = extract(arguments.executable, "methods", binary, directory / f"{binary.stem}.json")
            lines = run([str(binary)]).splitlines()
            require(len(lines) == 7, f"{binary.name}: expected seven runtime method identities")
            labels = set()
            for line in lines:
                label, owner_rva, code_rva, dictionary_rva, type_rva, argument_rvas = line.split("|")
                require(label not in labels, f"{binary.name}: duplicate runtime label {label}")
                labels.add(label)
                owner = base + int(owner_rva, 16)
                code = base + int(code_rva, 16)
                runtime_type = base + int(type_rva, 16)
                dictionary_rva_value = int(dictionary_rva, 16)
                dictionary = base + dictionary_rva_value if dictionary_rva_value else 0
                type_arguments = [base + int(rva, 16) for rva in argument_rvas.split(",") if rva]
                matches = [entry for entry in expected["methods"]
                           if entry["declaring_type"] == owner and entry["arguments"] == type_arguments
                           and (entry["dictionary"] == dictionary if dictionary else entry["entrypoint"] == code)]
                require(matches, f"{binary.name}: no extracted identity for {label}")
                for entry in matches:
                    require(entry["return_type_address"] == runtime_type,
                            f"{binary.name}: {label} return type differs from the runtime handle")
                    require(entry["parameter_type_addresses"] == [runtime_type],
                            f"{binary.name}: {label} parameter type differs from the runtime handle")
                    require(entry["vararg_type_addresses"] == [], f"{binary.name}: {label} unexpectedly has varargs")
            expected_labels = {"integer", "text", "integer_array", "text_array", "matrix", "mixed", "pointer"}
            require(labels == expected_labels, f"{binary.name}: runtime labels differ")
            print(f"method signatures: {binary.parent.name}, 7 return and parameter runtime handles")


def check_type_prefix(arguments):
    probe = arguments.probe.resolve()
    data = probe.read_bytes()
    base = image_base(data)
    with tempfile.TemporaryDirectory(prefix="aot-atlas-type-prefix-") as temporary:
        expected = extract(arguments.executable, "fields", probe, Path(temporary) / "fields.json")
    layouts = {layout["type"]: layout for layout in expected["layouts"]}
    fields = {(field["declaring_type"], field["field_name"]): field for field in expected["fields"]}
    field_count = size_count = 0
    for line in run([str(probe)]).splitlines():
        values = line.split("|")
        address = base + int(values[1], 16)
        if values[0] == "S":
            require(layouts[address]["length"] == int(values[2]), f"{line}: value size differs")
            size_count += 1
            continue
        require(values[0] == "F", f"unknown runtime observation: {line}")
        field = fields[address, values[2]]
        require(field["offset"] == int(values[3]) and field["size"] == int(values[4]),
                f"{line}: field extent differs")
        require(field["field_type"] == base + int(values[5], 16), f"{line}: field type differs")
        field_count += 1

    require(field_count == 12 and size_count == 7, "type-prefix fixture coverage differs")
    by_name = {layout["name"]: layout for layout in layouts.values()}
    require(by_name["CutWords"]["fields"][0][1:] == [0, 3], "CutWords prefix differs")
    require(by_name["CutNested"]["fields"][0][1:] == [0, 3], "CutNested prefix differs")
    require(by_name["CutReferences"]["fields"][0][1:] == [0, 12], "CutReferences prefix differs")
    print("type prefixes: 12 live fields and 7 live value sizes")


def check_utf16(arguments):
    encoded = arguments.json.read_bytes()
    text = json.loads(encoded)
    expected = struct.pack("<65536H", *range(65536))
    require(text.encode("utf-16-le", errors="surrogatepass") == expected,
            "JSON decoder did not recover every UTF-16 code unit")
    require(b"\x00" not in encoded and encoded.isascii(), "JSON output is not NUL-free ASCII")
    print("UTF-16 JSON: all 65,536 code units round-trip, including lone surrogates and NUL")


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description="Live runtime oracles for AOT Atlas output")
    subcommands = parser.add_subparsers(dest="check", required=True)

    enums = subcommands.add_parser("enums")
    enums.add_argument("runtime", type=Path)
    enums.add_argument("extraction", type=Path)
    enums.set_defaults(action=check_enums)

    linkage = subcommands.add_parser("linkage")
    linkage.add_argument("executable", type=Path)
    linkage.add_argument("folder", type=Path)
    linkage.set_defaults(action=check_linkage)

    managed = subcommands.add_parser("managed-abi")
    managed.add_argument("executable", type=Path)
    managed.add_argument("binaries", type=Path, nargs="+")
    managed.set_defaults(action=check_managed_abi)

    signatures = subcommands.add_parser("method-signatures")
    signatures.add_argument("executable", type=Path)
    signatures.add_argument("binaries", type=Path, nargs="+")
    signatures.set_defaults(action=check_method_signatures)

    prefixes = subcommands.add_parser("type-prefix")
    prefixes.add_argument("executable", type=Path)
    prefixes.add_argument("probe", type=Path)
    prefixes.set_defaults(action=check_type_prefix)

    utf16 = subcommands.add_parser("utf16")
    utf16.add_argument("json", type=Path)
    utf16.set_defaults(action=check_utf16)
    return parser.parse_args(argv)


def main(argv=None):
    arguments = parse_arguments(argv)
    arguments.action(arguments)


if __name__ == "__main__":
    main()
