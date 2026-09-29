using System.Buffers;
using System.Globalization;
using System.Runtime.InteropServices;
using Atlas;

internal static class HeaderOutput {
    internal static (int Types, int Fields, int References, int Unknown) Write(StreamWriter writer, string inputSha256, Extraction extraction) {
        var tables = CollectionsMarshal.AsSpan(extraction.Types.Types);
        var fields = CollectionsMarshal.AsSpan(extraction.Fields.FieldTypes);
        var maps = CollectionsMarshal.AsSpan(extraction.Maps.Fields);
        var layouts = extraction.Fields.Layouts.AsSpan();
        var locations = extraction.Fields.Fields.AsSpan();
        var names = new ArrayBufferWriter<char>(checked(tables.Length * 128 + fields.Length * 64 + 1));
        var typeNames = new IndexRange[tables.Length];
        var fieldNames = new IndexRange[fields.Length];
        for (int i = 0; i < tables.Length; ++i)
            typeNames[i] = Identifier(names, "atlas_", extraction.Names.Values[i], checked((uint)(tables[i].Address - extraction.Image.ImageBase)), -1);
        for (int i = 0; i < fields.Length; ++i) {
            ref readonly var field = ref fields[i];
            ref readonly var map = ref maps[field.MapIndex];
            fieldNames[i] = Identifier(names, "fieldmap_", map.Name, checked((uint)(tables[field.Owner - 1].Address - extraction.Image.ImageBase)), map.Vertex);
        }
        var identifiers = names.WrittenSpan;

        string guard = "ATLAS_LAYOUTS_" + inputSha256.ToUpperInvariant() + "_H";
        writer.Write("#ifndef "); writer.WriteLine(guard);
        writer.Write("#define "); writer.WriteLine(guard);
        writer.WriteLine("#include <stdint.h>\n");
        writer.WriteLine("#if UINTPTR_MAX != UINT64_MAX\n#error Atlas layouts require 64-bit pointers.\n#endif\n");
        // Binary Ninja needs the packed type attribute to retain non-aligned widths
        writer.WriteLine("#if defined(__clang__) || defined(__GNUC__)\n#define ATLAS_PACKED __attribute__((packed))\n#elif defined(_MSC_VER)\n#define ATLAS_PACKED\n#else\n#error Atlas layouts require Clang, GCC, or MSVC.\n#endif\n");
        writer.Write("// image_base: 0x"); writer.WriteLine(extraction.Image.ImageBase.ToString("X", CultureInfo.InvariantCulture));
        writer.Write("// map_format: "); writer.WriteLine(extraction.Maps.Format == MapFormat.Legacy ? "legacy" : "metadata");
        writer.WriteLine("struct atlas_method_table;\n");
        foreach (ref readonly var name in typeNames.AsSpan()) {
            writer.Write("struct "); writer.Write(identifiers.Slice(name.Start, name.Count)); writer.WriteLine(';');
        }
        writer.WriteLine();

        int unknown = 0;
        for (int i = 0; i < fields.Length; ++i) {
            ref readonly var map = ref maps[fields[i].MapIndex];
            if (fields[i].Size != 0 || map.Storage != 0 || map.Location != FieldLocation.Offset)
                continue;

            var name = fieldNames[i];
            writer.Write("#define atlas_unknown_size_offset_"); writer.Write(identifiers.Slice(name.Start, name.Count));
            writer.Write(" UINT32_C("); Number(writer, map.Value); writer.WriteLine(')');
            ++unknown;
        }
        writer.WriteLine("\n#pragma pack(push, 1)\n");

        var gc = new IndexRange[tables.Length];
        foreach (ref readonly var layout in CollectionsMarshal.AsSpan(extraction.Gc.Layouts)) {
            if (layout.RepeatStride == 0)
                gc[layout.TypeIndex] = layout.Runs;
        }
        int typesWritten = 0, fieldsWritten = 0, referencesWritten = 0;
        Span<char> referenceName = stackalloc char[13];
        "_ref_".CopyTo(referenceName);
        for (int i = 0; i < layouts.Length; ++i) {
            uint width = layouts[i].Length;
            if (width == 0)
                continue;

            var typeName = typeNames[i];
            writer.Write("struct ATLAS_PACKED "); writer.Write(identifiers.Slice(typeName.Start, typeName.Count)); writer.WriteLine(" {");
            writer.WriteLine("    union ATLAS_PACKED {");
            writer.Write("        uint8_t _layout_bytes["); Number(writer, width); writer.WriteLine("];");
            if (!tables[i].IsValueType) {
                writer.WriteLine("        struct atlas_method_table *__mt;");
            } else {
                string primitive = Primitive(tables[i].ElementType);
                if (primitive.Length != 0) {
                    writer.Write("        "); writer.Write(primitive); writer.WriteLine(" _value;");
                }
            }

            for (int owner = i; owner >= 0; owner = layouts[owner].BaseType - 1) {
                ref readonly var layout = ref layouts[owner];
                foreach (ref readonly var location in locations.Slice(layout.Fields.Start, layout.Fields.Count)) {
                    if (location.Offset >= width)
                        break;
                    ref readonly var field = ref fields[location.FieldIndex];
                    if (field.Size == 0)
                        continue;

                    string primitive = field.Binding != 0 && tables[field.Binding - 1].IsValueType
                        ? Primitive(tables[field.Binding - 1].ElementType) : "";
                    bool pointer = field.Storage is FieldStorageKind.Reference or FieldStorageKind.Pointer or FieldStorageKind.ByReference;
                    bool scalar = pointer || primitive.Length != 0;
                    uint extent = Math.Min(scalar ? field.Size : location.Extent, width - location.Offset);
                    bool prefix = extent < field.Size;
                    if (scalar && prefix && owner == i)
                        throw new InvalidDataException("A scalar field exceeds the exported instance layout.");

                    var range = fieldNames[location.FieldIndex];
                    var name = identifiers.Slice(range.Start, range.Count);
                    BeginMember(writer, name, location.Offset);
                    if (scalar && !prefix) {
                        if (field.Storage == FieldStorageKind.Reference && field.Binding != 0) {
                            var target = typeNames[field.Binding - 1];
                            writer.Write("struct "); writer.Write(identifiers.Slice(target.Start, target.Count)); writer.Write(" *");
                        } else {
                            writer.Write(pointer ? "void *" : primitive); writer.Write(' ');
                        }
                        writer.Write(name);
                    } else {
                        // Byte storage keeps the proven extent of an embedded value; the host C compiler must not infer its internal layout
                        writer.Write("uint8_t "); writer.Write(name); writer.Write(prefix ? "_prefix_bytes[" : "_bytes[");
                        Number(writer, extent); writer.Write(']');
                    }
                    writer.WriteLine(location.Offset == 0 ? ";" : "; };");
                    ++fieldsWritten;
                }
            }

            foreach (ref readonly var run in CollectionsMarshal.AsSpan(extraction.Gc.Runs).Slice(gc[i].Start, gc[i].Count)) {
                uint first = run.Offset - (tables[i].IsValueType ? 8U : 0);
                for (uint slot = 0; slot < run.Count; ++slot) {
                    uint offset = first + slot * 8;
                    if (offset > width || width - offset < 8)
                        throw new InvalidDataException("A GC reference exceeds the exported instance layout.");

                    offset.TryFormat(referenceName[5..], out int length, "X2", CultureInfo.InvariantCulture);
                    var name = referenceName[..(5 + length)];
                    BeginMember(writer, name, offset);
                    writer.Write("void *"); writer.Write(name);
                    writer.WriteLine(offset == 0 ? ";" : "; };");
                    ++referencesWritten;
                }
            }
            writer.WriteLine("    };\n};\n");
            ++typesWritten;
        }
        writer.WriteLine("#pragma pack(pop)\n#undef ATLAS_PACKED\n#endif");
        return (typesWritten, fieldsWritten, referencesWritten, unknown);
    }

    private static IndexRange Identifier(ArrayBufferWriter<char> arena, string prefix, string name, uint owner, int vertex) {
        int first = arena.WrittenCount;
        var text = arena.GetSpan(checked(prefix.Length + name.Length + 18));
        prefix.CopyTo(text);
        int length = prefix.Length;
        foreach (char value in name)
            text[length++] = value is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '_' ? value : '_';
        text[length++] = '_';
        owner.TryFormat(text[length..], out int digits, "X8", CultureInfo.InvariantCulture);
        length += digits;
        if (vertex >= 0) {
            text[length++] = '_';
            vertex.TryFormat(text[length..], out digits, "X8", CultureInfo.InvariantCulture);
            length += digits;
        }
        arena.Advance(length);
        return new IndexRange(first, length);
    }

    private static void BeginMember(StreamWriter writer, ReadOnlySpan<char> name, uint offset) {
        writer.Write("        ");
        if (offset != 0) {
            writer.Write("struct ATLAS_PACKED { uint8_t _prefix_"); writer.Write(name); writer.Write('[');
            Number(writer, offset); writer.Write("]; ");
        }
    }

    private static void Number(StreamWriter writer, uint value) {
        Span<char> text = stackalloc char[10];
        value.TryFormat(text, out int length, provider: CultureInfo.InvariantCulture);
        writer.Write(text[..length]);
    }

    private static string Primitive(int element) => element switch {
        2 or 5 => "uint8_t",
        4 => "int8_t",
        3 or 7 => "uint16_t",
        6 => "int16_t",
        8 => "int32_t",
        9 => "uint32_t",
        10 or 12 => "int64_t",
        11 or 13 => "uint64_t",
        14 => "float",
        15 => "double",
        _ => ""
    };
}
