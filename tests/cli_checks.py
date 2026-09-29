import argparse
import contextlib
import hashlib
import json
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run(command, check=True):
    process = subprocess.run(command, capture_output=True, text=True)
    if check and process.returncode != 0:
        raise RuntimeError(process.stderr.strip() or process.stdout.strip())
    return process


def check_publication(arguments):
    require(sys.platform == "win32", "publication checks require Windows file sharing")
    operation = "header" if arguments.header else "search" if arguments.query is not None else "extract"
    directory = Path(tempfile.mkdtemp(prefix="cli-publication-"))
    output = directory / ("output.h" if arguments.header else "output.json")
    invalid = directory / "invalid.exe"
    invalid.write_bytes(b"not a PE")

    expected = b"previous complete result"
    output.write_bytes(expected)
    digest = hashlib.sha256(arguments.binary.read_bytes()).hexdigest()
    randomizer = random.Random(0xA71A5)
    actions = ["valid", "invalid", "locked"]
    actions.extend(randomizer.choice(("valid", "invalid", "locked")) for _ in range(15))

    for action in actions:
        binary = invalid if action == "invalid" else arguments.binary
        command = [str(arguments.executable), operation, str(binary), str(output)]
        if arguments.query is not None:
            command.append(arguments.query)

        lock = output.open("rb") if action == "locked" else contextlib.nullcontext()
        with lock:
            process = run(command, check=False)

        expected_exit = 0 if action == "valid" else 1
        require(process.returncode == expected_exit,
                f"{action}: exit code {process.returncode}, expected {expected_exit}")
        if action == "valid":
            expected = output.read_bytes()
            if arguments.header:
                require(f"#ifndef ATLAS_LAYOUTS_{digest.upper()}_H\n".encode() in expected,
                        "header lacks its input-specific include guard")
                require(expected.endswith(b"#pragma pack(pop)\n#undef ATLAS_PACKED\n#endif\n"),
                        "header lacks its packing cleanup")
            else:
                value = json.loads(expected)
                require(value["operation"] == operation and value["input_sha256"] == digest,
                        "published JSON identifies the wrong operation or input")
        else:
            require(process.stderr.strip(), f"{action}: failure had no diagnostic")
            require(output.read_bytes() == expected, f"{action}: failure replaced the prior output")
        require(not list(directory.glob("*.tmp")), f"{action}: temporary output was not removed")

    print(f"publication: {len(actions)} transitions preserved complete output and removed temporary files")


def check_header(arguments):
    primitive = {
        2: "uint8_t", 3: "uint16_t", 4: "int8_t", 5: "uint8_t",
        6: "int16_t", 7: "uint16_t", 8: "int32_t", 9: "uint32_t",
        10: "int64_t", 11: "uint64_t", 12: "int64_t", 13: "uint64_t",
        14: "float", 15: "double",
    }
    with tempfile.TemporaryDirectory(prefix="aot-atlas-header-checks-") as temporary:
        directory = Path(temporary)
        for index, binary in enumerate(arguments.binaries):
            header = directory / f"{index}.h"
            process = run([str(arguments.executable), "header", str(binary), str(header)])
            require(process.returncode == 0, f"{binary.name}: header generation failed")
            content = header.read_bytes()
            require(b"\r" not in content and not content.startswith(b"\xef\xbb\xbf"),
                    f"{binary.name}: header is not plain LF-terminated ASCII")
            text = content.decode("ascii")
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            require(f"ATLAS_LAYOUTS_{digest.upper()}_H" in text,
                    f"{binary.name}: header guard does not identify the input")
            image_base = int(re.search(r"// image_base: (0x[0-9A-F]+)", text)[1], 16)

            outputs = {}
            for operation in ("fields", "types"):
                output = directory / f"{index}-{operation}.json"
                run([str(arguments.baseline), operation, str(binary), str(output)])
                outputs[operation] = json.loads(output.read_bytes())

            layouts = {entry["type"]: entry for entry in outputs["fields"]["layouts"]}
            fields = outputs["fields"]["fields"]
            types = {int(address): entry for address, entry in outputs["types"]["types"].items()}
            tags = {
                image_base + int(rva, 16): tag
                for tag, rva in re.findall(r"^struct (atlas_\w+_([0-9A-F]{8}));$", text, re.M)
            }
            definitions = {
                image_base + int(rva, 16): (tag, body)
                for tag, rva, body in re.findall(
                    r"^struct ATLAS_PACKED (atlas_\w+_([0-9A-F]{8})) \{\n(.*?)^\};",
                    text,
                    re.M | re.S,
                )
            }
            require(set(tags) == set(types), f"{binary.name}: forward declarations differ from runtime types")
            require(set(definitions) == {address for address, layout in layouts.items() if layout["length"]},
                    f"{binary.name}: structure definitions differ from known layouts")

            checks = [
                "#include <stddef.h>",
                "#pragma pack(push, 2)",
                f'#include "{header.name}"',
                f'#include "{header.name}"',
                "struct packing_probe { uint8_t a; uint64_t b; };",
                '_Static_assert(offsetof(struct packing_probe, b) == 2, "packing restored");',
                "#pragma pack(pop)",
            ]
            member_names = {}
            for address, (tag, body) in definitions.items():
                layout = layouts[address]
                width = layout["length"]
                checks.append(f'_Static_assert(sizeof(struct {tag}) == {width}, "layout width");')
                checks.append(f'_Static_assert(_Alignof(struct {tag}) == 1, "packed layout");')
                if layout["origin"] == "object":
                    checks.append(f'_Static_assert(offsetof(struct {tag}, __mt) == 0, "object header");')
                elif types[address]["element_type"] in primitive:
                    scalar = primitive[types[address]["element_type"]]
                    checks.append(
                        f'_Static_assert(_Generic(((struct {tag}*)0)->_value, '
                        f'{scalar}: 1, default: 0), "primitive type");')

                present = {}
                for member, owner, vertex in re.findall(
                        r"\b(fieldmap_\w+_([0-9A-F]{8})_([0-9A-F]{8})(?:_prefix_bytes|_bytes)?)\b", body):
                    key = (image_base + int(owner, 16), int(vertex, 16))
                    require(key not in present, f"{tag}: duplicate emitted member")
                    present[key] = member

                expected = {}
                owner = address
                while owner:
                    inherited = layouts[owner]
                    for field_index, offset, extent in inherited["fields"]:
                        field = fields[field_index]
                        if offset >= width or not field["size"]:
                            continue
                        key = (owner, field["field_map_vertex"])
                        expected[key] = field
                        member = present[key]
                        member_names[(address, field["field_name"])] = member
                        target = types.get(field["field_type"], {})
                        scalar = primitive.get(target.get("element_type"), "")
                        pointer = field["storage"] in ("Reference", "Pointer", "ByReference")
                        size = min(field["size"] if pointer or scalar else extent, width - offset)
                        checks.append(f'_Static_assert(offsetof(struct {tag}, {member}) == {offset}, "field offset");')
                        checks.append(f'_Static_assert(sizeof(((struct {tag}*)0)->{member}) == {size}, "field extent");')
                        if size == field["size"] and (pointer or scalar):
                            if field["storage"] == "Reference" and field["field_type"]:
                                c_type = f"struct {tags[field['field_type']]} *"
                            elif pointer:
                                c_type = "void *"
                            else:
                                c_type = scalar
                            checks.append(
                                f'_Static_assert(_Generic(((struct {tag}*)0)->{member}, '
                                f'{c_type}: 1, default: 0), "field type");')
                        else:
                            suffix = "_prefix_bytes" if size < field["size"] else "_bytes"
                            require(member.endswith(suffix), f"{tag}.{member}: byte-array suffix differs")
                    owner = inherited["base_type"]
                require(set(present) == set(expected), f"{tag}: emitted fields differ from the layout")

                gc = outputs["types"]["gc_layouts"].get(str(address), {})
                reference_offsets = set()
                if not gc.get("repeat_stride", 0):
                    for offset, count, _ in gc.get("runs", []):
                        adjustment = 8 if layout["origin"] == "payload" else 0
                        reference_offsets.update(offset + slot * 8 - adjustment for slot in range(count))
                emitted_references = set(re.findall(r"\b_ref_[0-9A-F]+\b", body))
                require(emitted_references == {f"_ref_{offset:02X}" for offset in reference_offsets},
                        f"{tag}: emitted GC slots differ from the GC layout")
                for offset in reference_offsets:
                    checks.append(f'_Static_assert(offsetof(struct {tag}, _ref_{offset:02X}) == {offset}, "GC offset");')

            instance_indices = {
                field_index
                for layout in layouts.values()
                for field_index, _, _ in layout["fields"]
            }
            expected_unknown = {
                (fields[index]["declaring_type"], fields[index]["field_map_vertex"]): fields[index]["offset"]
                for index in instance_indices
                if fields[index]["size"] == 0
            }
            actual_unknown = {}
            for macro, owner, vertex, offset in re.findall(
                    r"^#define (atlas_unknown_size_offset_fieldmap_\w+_([0-9A-F]{8})_([0-9A-F]{8})) UINT32_C\((\d+)\)$",
                    text,
                    re.M):
                actual_unknown[(image_base + int(owner, 16), int(vertex, 16))] = int(offset)
                checks.append(f'_Static_assert({macro} == {offset}, "unknown-size field offset");')
            require(actual_unknown == expected_unknown,
                    f"{binary.name}: unknown-size field macros differ from the field map")

            if arguments.runtime:
                runtime = run([str(binary.resolve())]).stdout
                observed = 0
                for line in runtime.splitlines():
                    parts = line.split("|")
                    address = image_base + int(parts[1], 16)
                    tag = tags[address]
                    if parts[0] == "S":
                        checks.append(f'_Static_assert(sizeof(struct {tag}) == {int(parts[2])}, "live value size");')
                    else:
                        require(parts[0] == "F", f"{binary.name}: unknown runtime observation")
                        member = member_names[(address, parts[2])]
                        checks.append(f'_Static_assert(offsetof(struct {tag}, {member}) == {int(parts[3])}, "live field offset");')
                        if not member.endswith("_prefix_bytes"):
                            checks.append(
                                f'_Static_assert(sizeof(((struct {tag}*)0)->{member}) == '
                                f'{int(parts[4])}, "live field size");')
                    observed += 1
                require(observed > 0, f"{binary.name}: runtime probe produced no observations")

            source = directory / f"{index}.c"
            source.write_text("\n".join(checks) + "\n", encoding="ascii")
            compiled = run([
                arguments.compiler, "-x", "c", "-std=c11", "-pedantic-errors",
                "-Wall", "-Wextra", "-Werror", "-fsyntax-only", str(source),
            ], check=False)
            require(compiled.returncode == 0, compiled.stderr[:4000])

            run([str(arguments.executable), "header", str(binary), str(header)])
            require(header.read_bytes() == content, f"{binary.name}: repeated header output changed")
            map_format = re.search(r"// map_format: (legacy|metadata)", text)[1]
            run([str(arguments.executable), "header", str(binary), str(header), "--map-format", map_format])
            require(header.read_bytes() == content,
                    f"{binary.name}: explicit map format changed the generated header")
            print(f"header: {binary.name}, {len(definitions)} layouts, {len(checks) - 7} compiled assertions")


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description="AOT Atlas CLI integration checks")
    subcommands = parser.add_subparsers(dest="check", required=True)

    publication = subcommands.add_parser("publication")
    publication.add_argument("executable", type=Path)
    publication.add_argument("binary", type=Path)
    mode = publication.add_mutually_exclusive_group()
    mode.add_argument("--query")
    mode.add_argument("--header", action="store_true")
    publication.set_defaults(action=check_publication)

    header = subcommands.add_parser("header")
    header.add_argument("executable", type=Path)
    header.add_argument("binaries", type=Path, nargs="+")
    header.add_argument("--baseline", required=True, type=Path)
    header.add_argument("--runtime", action="store_true")
    header.add_argument("--compiler", default="clang")
    header.set_defaults(action=check_header)
    return parser.parse_args(argv)


def main(argv=None):
    arguments = parse_arguments(argv)
    arguments.action(arguments)


if __name__ == "__main__":
    main()
