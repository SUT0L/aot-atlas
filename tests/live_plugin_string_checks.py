"""Run check_live_strings inside the connected Binary Ninja MCP host on a fresh DictionaryProbe view."""

import ctypes


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


def check_live_strings(view, plugin_path, wait_for_analysis):
    candidates = ((0xF13D8, 11), (0xF13E3, 11), (0xF13EE, 23))
    addresses = [view.start + rva for rva, _ in candidates]
    for address, _ in zip(addresses, candidates):
        variable = view.get_data_var_at(address)
        require(variable is not None and variable.auto_discovered,
                f"Expected fresh automatic string storage at 0x{address:X}")

    plugin = ctypes.CDLL(str(plugin_path))
    plugin.AtlasApplyMetadata.argtypes = [ctypes.c_void_p, ctypes.c_uint8, ctypes.POINTER(ApplyStats)]
    plugin.AtlasApplyMetadata.restype = ctypes.c_int

    def apply():
        stats = ApplyStats()
        status = plugin.AtlasApplyMetadata(ctypes.cast(view.handle, ctypes.c_void_p), 0, ctypes.byref(stats))
        require(status == 0, f"Atlas apply returned {status}")
        return stats

    def check_arrays():
        for address, (_, width) in zip(addresses, candidates):
            variable = view.get_data_var_at(address)
            require(variable is not None and not variable.auto_discovered,
                    f"Atlas string type disappeared at 0x{address:X}")
            require(variable.type.width == width and str(variable.type).startswith("char["),
                    f"Atlas string has the wrong type at 0x{address:X}: {variable.type}")

    first = apply()
    check_arrays()
    wait_for_analysis()
    second = apply()
    check_arrays()
    require(second.data_variables == first.data_variables,
            "Repeat application changed the number of defined variables")

    edited_address = addresses[0]
    view.define_user_data_var(edited_address, "uint32_t")
    third = apply()
    edited = view.get_data_var_at(edited_address)
    require(edited is not None and not edited.auto_discovered and str(edited.type) == "uint32_t",
            "Repeat application replaced an analyst's string type")
    require(third.data_variables + 1 == second.data_variables,
            "A preserved user variable was counted as an Atlas definition")
    for address, (_, width) in zip(addresses[1:], candidates[1:]):
        variable = view.get_data_var_at(address)
        require(variable is not None and not variable.auto_discovered and variable.type.width == width,
                f"Another Atlas string disappeared at 0x{address:X}")

    return first.data_variables, second.data_variables, third.data_variables
