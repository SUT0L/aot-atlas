import struct


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def field_record(view):
    data = bytes(view.query_metadata("aot-atlas:field-references"))
    require(data[:8] == b"ATFLD002" and len(data) >= 16,
            "field references are not published in the named receiver format")
    count = struct.unpack_from("<i", data, 8)[0]
    require(0 <= count <= (len(data) - 16) // 20, "field reference count is invalid")
    records = [struct.unpack_from("<IIIII", data, 12 + 20 * index)
               for index in range(count)]
    position = 12 + 20 * count
    name_count = struct.unpack_from("<i", data, position)[0]
    position += 4
    require(0 <= name_count <= count, "field receiver name count is invalid")
    names = {}
    for _ in range(name_count):
        require(position + 9 <= len(data), "field receiver name is truncated")
        type_rva, scope, length = struct.unpack_from("<IBi", data, position)
        position += 9
        require(scope in (0, 1) and 0 < length <= len(data) - position,
                "field receiver name is invalid")
        leaf = data[position:position + length].decode("utf-8")
        position += length
        require("\0" not in leaf and type_rva not in names,
                "field receiver name is duplicated or contains a NUL")
        names[type_rva] = (scope, leaf)
    require(position == len(data) and {record[0] for record in records} == names.keys(),
            "field receiver names do not match the reference records")
    return records, names


def verify_host_references(view, records, names):
    for type_rva, offset, function_rva, instruction_rva, size in records:
        scope, leaf = names[type_rva]
        expected = "atlas::" + ("opaque" if scope else "runtime") + "::" + leaf
        function = view.get_function_at(view.start + function_rva)
        require(function is not None, f"field function 0x{view.start + function_rva:X} is absent")
        references = view.get_code_refs_for_type_fields_from(
            view.start + instruction_rva, func=function, length=size if size else None)
        require(any(str(reference.name) == expected and reference.offset == offset
                    for reference in references),
                f"field reference 0x{view.start + instruction_rva:X} is absent")


def check_reloaded_fields(original, restored, apply_fields):
    before, names = field_record(original)
    require(len(before) >= 6, "property fixture does not exercise field references")
    opaque = [type_rva for type_rva, (scope, _) in names.items() if scope == 1]
    require(opaque, "property fixture does not exercise an opaque field receiver")
    verify_host_references(original, before, names)

    missing = [type_rva for type_rva in opaque
               if restored.get_type_name_by_id(f"aot-atlas:runtime-type:v1:{type_rva:08X}") is None]
    require(missing, "saved database did not exercise a missing opaque type ID")
    require(apply_fields(restored) == 0, "field references did not reapply after database reload")
    restored.update_analysis_and_wait()

    after, restored_names = field_record(restored)
    require((after, restored_names) == (before, names),
            "field evidence changed after database reload")
    verify_host_references(restored, after, restored_names)
    return {"references": len(after), "opaque_receivers_without_type_id": len(missing)}


def check_legacy_recovery(view, apply_fields):
    require(bytes(view.query_metadata("aot-atlas:field-references"))[:8] == b"ATFLD001",
            "legacy fixture does not contain the original field record")
    require(apply_fields(view) == 0, "legacy field references did not recover")
    view.update_analysis_and_wait()
    records, names = field_record(view)
    verify_host_references(view, records, names)
    return {"recovered_references": len(records)}
