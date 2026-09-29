using System.Runtime.InteropServices;
using System.Text;
using System.Text.Unicode;

namespace Atlas.Binja;

internal enum StaticRecord : byte {
    Allocation, Cell, ThreadIndex, Constructor, Generic, Field
}

internal static class StaticText {
    internal static int BufferLength(Extraction extraction) {
        int typeLength = 0, fieldLength = 0;
        foreach (string name in extraction.Names.Values)
            typeLength = Math.Max(typeLength, name.Length);
        foreach (ref readonly var field in CollectionsMarshal.AsSpan(extraction.Maps.Fields))
            fieldLength = Math.Max(fieldLength, field.Name.Length);
        return checked(Encoding.UTF8.GetMaxByteCount(typeLength + fieldLength) + 320);
    }

    internal static int Write(Extraction extraction, StaticRecord kind, int index, Span<byte> output) {
        var statics = extraction.Statics;
        ulong imageBase = extraction.Image.ImageBase;
        int length;
        if (kind == StaticRecord.Allocation) {
            ref readonly var entry = ref CollectionsMarshal.AsSpan(statics.Allocations)[index];
            string source = extraction.Memory.Regions[extraction.Memory.Find(entry.Address)].Hydrated ? "rehydrated" : "file";
            Utf8.TryWrite(output, $"statics::allocation::{entry.Address - imageBase:X8}::record_bytes[{source}]::object_size[{entry.BaseSize - 8}]::gc_series[{entry.Runs.Count}]", out length);
        } else if (kind == StaticRecord.Cell) {
            ref readonly var entry = ref CollectionsMarshal.AsSpan(statics.GcCells)[index];
            Utf8.TryWrite(output, $"rtr::201::gc_cell::{entry.Cell - imageBase:X8}::initial_flags[{entry.Flags}]::descriptor[{entry.Descriptor - imageBase:X8}]", out length);
            if (entry.PreinitData != 0) {
                Utf8.TryWrite(output[length..], $"::preinit[{entry.PreinitData - imageBase:X8}]", out int written);
                length += written;
            }
        } else if (kind == StaticRecord.ThreadIndex) {
            ref readonly var entry = ref CollectionsMarshal.AsSpan(statics.ThreadIndices)[index];
            string source = extraction.Memory.Regions[extraction.Memory.Find(entry.Address)].Hydrated ? "rehydrated" : "file";
            Utf8.TryWrite(output, $"rtr::202::thread_index::{entry.Address - imageBase:X8}::record_bytes[{source}]::index[{entry.Index}]::inlined_offset[{entry.InlinedOffset}]::descriptor[{entry.Descriptor - imageBase:X8}]", out length);
        } else if (kind == StaticRecord.Constructor) {
            ref readonly var entry = ref CollectionsMarshal.AsSpan(statics.Constructors)[index];
            string name = extraction.Names.Values[extraction.Types.Index[entry.Type]];
            Utf8.TryWrite(output, $"rtr::310::{entry.Vertex:X8}::{name}::nongc_base[{entry.NonGcBase - imageBase:X8}]", out length);
        } else if (kind == StaticRecord.Generic) {
            ref readonly var entry = ref CollectionsMarshal.AsSpan(statics.Generics)[index];
            string name = extraction.Names.Values[extraction.Types.Index[entry.Type]];
            Utf8.TryWrite(output, $"rtr::334::{entry.Vertex:X8}::{name}", out length);
            if (entry.NonGcBase != 0) {
                Utf8.TryWrite(output[length..], $"::nongc_base[{entry.NonGcBase - imageBase:X8}]", out int written);
                length += written;
            }
            if (entry.GcCell != 0) {
                Utf8.TryWrite(output[length..], $"::gc_cell[{entry.GcCell - imageBase:X8}]", out int written);
                length += written;
            }
            if (entry.ThreadIndex != 0) {
                Utf8.TryWrite(output[length..], $"::thread_index[{entry.ThreadIndex - imageBase:X8}]", out int written);
                length += written;
            }
        } else {
            ref readonly var entry = ref CollectionsMarshal.AsSpan(statics.Fields)[index];
            ref readonly var field = ref CollectionsMarshal.AsSpan(extraction.Maps.Fields)[entry.FieldMapIndex];
            string owner = extraction.Names.Values[extraction.Types.Index[field.DeclaringType]];
            string location = entry.Location switch {
                StaticLocation.NonGcAddress => "nongc_address",
                StaticLocation.GcObject => "gc_object",
                StaticLocation.ThreadObject => "thread_object",
                StaticLocation.RuntimeBase => "runtime_base",
                StaticLocation.Ordinal => "ordinal",
                _ => "unknown"
            };
            string coordinate = entry.Location == StaticLocation.Ordinal ? "ordinal" : "offset";
            Utf8.TryWrite(output, $"rtr::309::{field.Vertex:X8}::{owner}::{field.Name}::{location}::{coordinate}[{entry.Offset}]", out length);
            if (entry.Address != 0) {
                Utf8.TryWrite(output[length..], $"::address[{entry.Address - imageBase:X8}]", out int written);
                length += written;
            }
            if (entry.Descriptor != 0) {
                Utf8.TryWrite(output[length..], $"::descriptor[{entry.Descriptor - imageBase:X8}]", out int written);
                length += written;
            }
        }
        output[length] = 0;
        return length;
    }
}
