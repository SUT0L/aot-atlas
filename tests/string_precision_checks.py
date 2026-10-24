import argparse
import hashlib
import json
import struct
import subprocess
from pathlib import Path


EXPECTED_BYTES = {
    0: b"Atlas native ASCII candidate\0",
    1: b'Atlas "quote" \\ slash\tline\n\0',
    2: "Atlas wide text\0".encode("utf-16le"),
    3: struct.pack("<7H", 0x6100, 0x6362, 0x0064, 0x0065, 0x0066, 0x0067, 0),
    4: b"ABCD\0",
    5: struct.pack("<5H", 0x41, 0x42, 0x43, 0x44, 0),
    6: b"OK\0",
    7: "Yes\0".encode("utf-16le"),
    8: bytes((0xFF, 0x03, 0xFE, 0)),
}

TEXT_CASES = {0, 1, 2, 6, 7}
BINARY_CASES = {4, 5, 8}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def preferred_image_base(binary):
    data = binary.read_bytes()
    require(data[:2] == b"MZ", "String probe is not a PE file")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    require(data[pe:pe + 4] == b"PE\0\0", "String probe has no PE header")
    optional = pe + 24
    require(struct.unpack_from("<H", data, optional)[0] == 0x20B,
            "String probe is not PE32+")
    return struct.unpack_from("<Q", data, optional + 24)[0]


def source_labels(oracle, image_base):
    labels = {}
    for line in oracle.splitlines():
        index_text, rva_text, hex_text = line.split("|")
        index = int(index_text)
        require(index not in labels and index in EXPECTED_BYTES,
                f"Unexpected or duplicate probe label {index}")
        actual_bytes = bytes.fromhex(hex_text)
        require(actual_bytes == EXPECTED_BYTES[index],
                f"Probe {index} no longer contains the labelled source bytes")
        labels[index] = image_base + int(rva_text, 16)
    require(labels.keys() == EXPECTED_BYTES.keys(), "String probe omitted a source label")
    return labels


def main():
    parser = argparse.ArgumentParser(description="Check native string candidate precision against source labels")
    parser.add_argument("cli", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("oracle", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()

    binary = arguments.binary.resolve()
    labels = source_labels(arguments.oracle.read_text(encoding="utf-8"), preferred_image_base(binary))
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(arguments.cli), "strings", str(binary), str(arguments.output)],
                   check=True, capture_output=True, text=True)
    report = json.loads(arguments.output.read_bytes())
    require(report["operation"] == "strings" and report["schema_version"] == 1,
            "String command returned an unexpected document")
    require(report["input_sha256"] == hashlib.sha256(binary.read_bytes()).hexdigest(),
            "String report does not describe the labelled probe")
    require(report["candidate_section"] == ".rdata" and report["scanned_sections"] == 1,
            "String scan coverage changed")
    require(report["minimum_ascii_bytes"] == 4 and report["minimum_utf16le_bytes"] == 8,
            "String candidate minimum lengths changed")

    candidates = {entry["address"]: entry for entry in report["strings"]}
    require(len(candidates) == len(report["strings"]), "String report repeats an address")
    require(all(entry["evidence"] == "nul_terminated_printable_bytes"
                for entry in candidates.values()), "String candidates claim semantic proof")

    found_text = {index for index in TEXT_CASES if labels[index] in candidates}
    found_binary = {index for index in BINARY_CASES if labels[index] in candidates}
    require({0, 1, 2} <= found_text, "Known longer strings were missed")
    require(8 not in found_binary, "Nonprintable binary data became a string candidate")
    require(len(found_binary) <= 2, "Binary false positives exceeded the labelled bound")
    require(len(TEXT_CASES - found_text) <= 2, "String false negatives exceeded the labelled bound")

    for index in found_text | found_binary:
        candidate = candidates[labels[index]]
        wide = index in (2, 5, 7)
        expected = EXPECTED_BYTES[index][:-2 if wide else -1]
        require(candidate["encoding"] == ("utf-16le" if wide else "ascii")
                and candidate["byte_length"] == len(expected),
                f"Probe {index} candidate encoding or extent is wrong")

    print(f"Source labelled native strings: true positives {len(found_text)}, "
          f"false positives {len(found_binary)}, "
          f"false negatives {len(TEXT_CASES - found_text)}, "
          f"true negatives {len(BINARY_CASES - found_binary)}")


if __name__ == "__main__":
    main()
