"""Run check_live_strings inside the connected Binary Ninja MCP host on a fresh StringProbe view."""

import ctypes
import struct
from pathlib import Path

from string_precision_checks import preferred_image_base, source_labels


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


def plugin_at(path):
    plugin = ctypes.CDLL(str(path))
    plugin.AtlasApplyMetadata.argtypes = [ctypes.c_void_p, ctypes.c_uint8, ctypes.POINTER(ApplyStats)]
    plugin.AtlasApplyMetadata.restype = ctypes.c_int
    return plugin


def apply(plugin, view):
    stats = ApplyStats()
    status = plugin.AtlasApplyMetadata(ctypes.cast(view.handle, ctypes.c_void_p), 0, ctypes.byref(stats))
    require(status == 0, f"Atlas apply returned {status}")
    return stats


def owned_fact_count(view):
    receipt = view.query_metadata("aot-atlas:owned-annotations")
    require(isinstance(receipt, bytes) and receipt[:8] == b"ATOWN001",
            "Atlas ownership receipt is missing or has the wrong format")
    snapshot_bytes = struct.unpack_from("<I", receipt, 8)[0]
    require(12 + snapshot_bytes + 4 <= len(receipt), "Atlas ownership receipt is truncated")
    return struct.unpack_from("<I", receipt, 12 + snapshot_bytes)[0]


def check_live_strings(view, plugin_path, binary_path, oracle_path, wait_for_analysis,
                       old_plugin_path=None):
    binary = Path(binary_path)
    image_base = preferred_image_base(binary)
    labels = source_labels(Path(oracle_path).read_text(encoding="utf-8"), image_base)
    addresses = {index: view.start + address - image_base for index, address in labels.items()}
    candidate_labels = (0, 1, 2, 4, 5)
    binary_labels = (4, 5)

    def candidate_symbol(address):
        symbol = view.get_symbol_at(address)
        return symbol is not None and symbol.raw_name.startswith("candidate::cstring::")

    def check_candidates():
        for index in candidate_labels:
            address = addresses[index]
            variable = view.get_data_var_at(address)
            require(variable is None or variable.auto_discovered,
                    f"Candidate {index} acquired a user string type at 0x{address:X}")
            require(not candidate_symbol(address),
                    f"Candidate {index} acquired an Atlas string symbol at 0x{address:X}")
            encoding = "utf16le" if index in (2, 5) else "ascii"
            require(any(tag.type.name == "AOT Atlas printable bytes"
                        and tag.data.startswith(f"bytes::{encoding}::nul_terminated::")
                        for tag in view.get_tags_at(address)),
                    f"Candidate {index} lost its byte evidence tag at 0x{address:X}")
            require(not any(tag.type.name == "AOT Atlas strings"
                            for tag in view.get_tags_at(address)),
                    f"Candidate {index} retained a misleading string tag at 0x{address:X}")

        for index in (6, 7, 8):
            address = addresses[index]
            require(not any(tag.data.startswith("bytes::") for tag in view.get_tags_at(address)),
                    f"Noncandidate {index} acquired an Atlas string tag at 0x{address:X}")

    if old_plugin_path is not None:
        apply(plugin_at(old_plugin_path), view)
        for index in binary_labels:
            address = addresses[index]
            variable = view.get_data_var_at(address)
            require(variable is not None and not variable.auto_discovered and candidate_symbol(address),
                    f"Old plugin did not reproduce the false string at 0x{address:X}")

    plugin = plugin_at(plugin_path)
    first = apply(plugin, view)
    check_candidates()
    first_facts = owned_fact_count(view)

    wait_for_analysis()
    second = apply(plugin, view)
    check_candidates()
    require(owned_fact_count(view) == first_facts,
            "Repeat application changed the annotation ownership count")
    require(second.data_variables == first.data_variables,
            "Repeat application changed the owned variable count")

    binary_address = addresses[4]
    view.define_user_data_var(binary_address, "uint32_t")
    third = apply(plugin, view)
    edited = view.get_data_var_at(binary_address)
    require(edited is not None and not edited.auto_discovered and str(edited.type) == "uint32_t",
            "Repeat application replaced an analyst's binary type")
    require(not candidate_symbol(binary_address), "Repeat application restored a speculative string symbol")
    require(third.data_variables == second.data_variables,
            "An analyst's binary variable changed Atlas's owned variable count")

    return first.data_variables, second.data_variables, third.data_variables
