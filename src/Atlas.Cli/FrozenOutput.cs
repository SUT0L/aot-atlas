using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class FrozenOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, Extraction extraction) {
        var frozen = extraction.Frozen;
        var tables = extraction.Types;
        var names = extraction.Names;
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("region_start", frozen.Start);
        json.WriteNumber("region_length", frozen.Data.Length);
        json.WriteString("region_storage", frozen.Data.IsEmpty ? "absent"
            : extraction.Memory.Regions[extraction.Memory.Find(frozen.Start)].Hydrated ? "rehydrated" : "file");
        json.WriteNumber("frozen_seconds", extraction.FrozenSeconds);
        json.WriteNumber("null_references", frozen.NullReferences);
        json.WriteStartArray("objects");
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(frozen.Objects)) {
            ref readonly var type = ref CollectionsMarshal.AsSpan(tables.Types)[entry.TypeIndex];
            ulong address = frozen.Start + (uint)entry.Offset;
            var data = frozen.Data.Span.Slice(entry.Data.Start, entry.Data.Count);
            json.WriteStartObject();
            json.WriteNumber("address", address);
            json.WriteString("name", $"frozen_ref_{address:X}");
            json.WriteNumber("methodtable", type.Address);
            json.WriteString("type", names.Values[entry.TypeIndex]);
            json.WriteString("kind", entry.Kind.ToString());
            json.WriteNumber("allocation_size", entry.AllocationSize);
            json.WriteNumber("data_address", frozen.Start + (uint)entry.Data.Start);
            json.WriteNumber("data_length", entry.Data.Count);
            if (entry.Kind == FrozenKind.String) {
                json.WriteNumber("length", entry.Count);
                json.WriteBase64String("utf16le", data);
                json.WriteBoolean("unpaired_surrogate", entry.UnpairedSurrogate);
                if (!entry.UnpairedSurrogate)
                    json.WriteString("text", MemoryMarshal.Cast<byte, char>(data));
            } else {
                json.WriteBase64String("initial_data", frozen.Data.Span.Slice(entry.Offset + 8, entry.AllocationSize - 16));
                if (entry.Kind == FrozenKind.Array) {
                    json.WriteNumber("count", entry.Count);
                    json.WriteNumber("component_size", type.ComponentSize);
                    json.WriteNumber("element_type", type.RelatedType);
                    int elementIndex = tables.Index[type.RelatedType];
                    ref readonly var element = ref CollectionsMarshal.AsSpan(tables.Types)[elementIndex];
                    json.WriteString("element_name", names.Values[elementIndex]);
                    if (type.ElementType == 0x17) {
                        int rank = checked((int)(type.BaseSize - 24) / 8);
                        json.WriteStartArray("dimensions");
                        for (int i = 0; i < rank; ++i)
                            json.WriteNumberValue(BinaryPrimitives.ReadInt32LittleEndian(frozen.Data.Span[(entry.Offset + 16 + i * 4)..]));
                        json.WriteEndArray();
                        json.WriteStartArray("lower_bounds");
                        for (int i = 0; i < rank; ++i)
                            json.WriteNumberValue(BinaryPrimitives.ReadInt32LittleEndian(frozen.Data.Span[(entry.Offset + 16 + rank * 4 + i * 4)..]));
                        json.WriteEndArray();
                    }

                    bool primitive = element.IsValueType && element.ElementType is >= 2 and <= 0x0F;
                    bool reference = (element.Kind == 0 && element.ElementType is >= 0x14 and <= 0x16)
                        || (element.Kind == 2 && element.ElementType is 0x17 or 0x18);
                    if (primitive || reference) {
                        int count = Math.Min(entry.Count, 256);
                        json.WriteBoolean("values_truncated", count != entry.Count);
                        json.WriteStartArray(reference ? "elements" : "values");
                        for (int i = 0; i < count; ++i) {
                            var value = data[(i * type.ComponentSize)..];
                            if (reference)
                                json.WriteNumberValue(BinaryPrimitives.ReadUInt64LittleEndian(value));
                            else
                                WritePrimitive(json, value, element.ElementType);
                        }
                        json.WriteEndArray();
                    }
                } else if (entry.Kind == FrozenKind.Box && type.ElementType is >= 2 and <= 0x0F) {
                    json.WritePropertyName("value");
                    WritePrimitive(json, data, type.ElementType);
                }
            }

            json.WriteStartArray("references");
            for (int i = entry.References.Start; i < entry.References.End; ++i) {
                ref readonly var reference = ref CollectionsMarshal.AsSpan(frozen.References)[i];
                json.WriteStartObject();
                json.WriteString("name", $"_ref_{reference.Offset:X}");
                json.WriteNumber("offset", reference.Offset);
                json.WriteNumber("target", frozen.Start + (uint)frozen.Objects[reference.Target].Offset);
                json.WriteEndObject();
            }
            json.WriteEndArray();
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteEndObject();
    }

    private static void WritePrimitive(Utf8JsonWriter json, ReadOnlySpan<byte> data, int element) {
        switch (element) {
            case 2:
                json.WriteBooleanValue(data[0] != 0);
                break;
            case 3:
            case 7:
                json.WriteNumberValue(BinaryPrimitives.ReadUInt16LittleEndian(data));
                break;
            case 4:
                json.WriteNumberValue((sbyte)data[0]);
                break;
            case 5:
                json.WriteNumberValue(data[0]);
                break;
            case 6:
                json.WriteNumberValue(BinaryPrimitives.ReadInt16LittleEndian(data));
                break;
            case 8:
                json.WriteNumberValue(BinaryPrimitives.ReadInt32LittleEndian(data));
                break;
            case 9:
                json.WriteNumberValue(BinaryPrimitives.ReadUInt32LittleEndian(data));
                break;
            case 10:
            case 12:
                json.WriteNumberValue(BinaryPrimitives.ReadInt64LittleEndian(data));
                break;
            case 11:
            case 13:
                json.WriteNumberValue(BinaryPrimitives.ReadUInt64LittleEndian(data));
                break;
            case 14:
            case 15:
                double value = element == 14 ? BinaryPrimitives.ReadSingleLittleEndian(data) : BinaryPrimitives.ReadDoubleLittleEndian(data);
                if (double.IsFinite(value))
                    json.WriteNumberValue(value);
                else
                    json.WriteStringValue(double.IsNaN(value) ? "NaN" : value < 0 ? "-Infinity" : "+Infinity");
                break;
            default:
                throw new InvalidDataException("Unknown primitive element code.");
        }
    }
}
