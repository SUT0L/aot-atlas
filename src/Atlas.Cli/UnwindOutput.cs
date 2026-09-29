using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class UnwindOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, PeImage image, UnwindTables tables) {
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("image_base", image.ImageBase);
        json.WriteNumber("directory_rva", image.ExceptionRva);
        json.WriteNumber("directory_count", tables.DirectoryCount);
        json.WriteStartArray("entries");
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(tables.Entries)) {
            json.WriteStartObject();
            json.WriteNumber("rva", entry.Address);
            json.WriteNumber("begin", entry.Function.Begin);
            json.WriteNumber("end", entry.Function.End);
            json.WriteNumber("unwind", entry.Function.Unwind);
            json.WriteBoolean("indirect", entry.Indirect);
            json.WriteNumber("parent", entry.Parent == 0 ? 0 : tables.Entries[entry.Parent - 1].Address);
            json.WriteNumber("root", tables.Entries[entry.Root - 1].Address);
            json.WriteEndObject();
        }
        json.WriteEndArray();

        json.WriteStartArray("unwind_info");
        foreach (ref readonly var info in CollectionsMarshal.AsSpan(tables.Infos)) {
            json.WriteStartObject();
            json.WriteNumber("rva", info.Address);
            json.WriteNumber("version", info.Version);
            json.WriteNumber("flags", info.Flags);
            json.WriteNumber("prolog_size", info.PrologSize);
            json.WriteNumber("slots", info.SlotCount);
            json.WriteNumber("frame_register", info.Frame & 15);
            json.WriteNumber("frame_offset", (info.Frame >> 4) * 16);
            json.WriteNumber("length", info.Length);
            json.WriteNumber("handler", info.Handler);
            json.WriteNumber("chained_entry", info.ChainedEntry == 0 ? 0 : tables.Entries[info.ChainedEntry - 1].Address);
            json.WriteString("bytes", Convert.ToHexStringLower(image.FileSpan(image.ImageBase + info.Address, info.Length)));
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteEndObject();
    }
}
