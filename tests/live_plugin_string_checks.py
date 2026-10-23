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
    candidates = ((0xF39E8, 7), (0xF3BD8, 7), (0xF3BE0, 5))
    addresses = [view.start + rva for rva, _ in candidates]
    unreferenced = [view.start + rva for rva in (0xF13D8, 0x11DDF7, 0x121E37)]
    for address in addresses:
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
            require(variable.type.width == width and str(variable.type).startswith("char const["),
                    f"Atlas string has the wrong type at 0x{address:X}: {variable.type}")

    def check_unreferenced():
        for address in unreferenced:
            variable = view.get_data_var_at(address)
            require(variable is None or variable.auto_discovered,
                    f"Unreferenced candidate acquired a user data type at 0x{address:X}")
            symbol = view.get_symbol_at(address)
            require(symbol is None or not symbol.name.startswith("candidate::cstring::"),
                    f"Unreferenced candidate acquired an Atlas symbol at 0x{address:X}")
            require(any(tag.data.startswith("bytes::ascii::nul_terminated::")
                        for tag in view.get_tags_at(address)),
                    f"Unreferenced candidate lost its low impact tag at 0x{address:X}")

    first = apply()
    check_arrays()
    check_unreferenced()
    wait_for_analysis()
    second = apply()
    check_arrays()
    check_unreferenced()
    require(second.data_variables == first.data_variables,
            "Repeat application changed the number of defined variables")

    edited_address = addresses[0]
    view.define_user_data_var(edited_address, "uint32_t")
    third = apply()
    check_unreferenced()
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
