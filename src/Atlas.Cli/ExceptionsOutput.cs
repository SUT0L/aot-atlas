using System.Text.Json;
using Atlas;

internal static class ExceptionsOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, PeImage image, UnwindTables unwind, ManagedUnwind managed) {
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("image_base", image.ImageBase);
        json.WriteString("region_source", managed.RegionSource switch {
            ManagedRegionSource.Pogo => "pogo::.managedcode$I",
            ManagedRegionSource.Section => "section::.managed",
            _ => "unknown"
        });
        json.WriteNumber("region_start", managed.RegionStart);
        json.WriteNumber("region_length", managed.RegionLength);
        if (managed.RegionSource == ManagedRegionSource.Pogo)
            json.WriteNumber("region_record_file_offset", managed.RegionRecord);
        else if (managed.RegionSource == ManagedRegionSource.Section)
            json.WriteNumber("region_section_index", managed.RegionRecord);

        json.WriteStartArray("frames");
        foreach (ref readonly var frame in managed.Frames.AsSpan()) {
            var entry = unwind.Entries[frame.Entry - 1];
            var root = unwind.Entries[managed.Frames[frame.Root - 1].Entry - 1];
            json.WriteStartObject();
            json.WriteNumber("rva", entry.Address);
            json.WriteNumber("begin", entry.Function.Begin);
            json.WriteNumber("end", entry.Function.End);
            json.WriteNumber("root", root.Function.Begin);
            json.WriteNumber("method_end", managed.Frames[frame.Root - 1].MethodEnd);
            json.WriteNumber("trailer_rva", frame.Trailer);
            json.WriteNumber("header_length", frame.HeaderLength);
            json.WriteString("header_bytes", Convert.ToHexStringLower(image.FileSpan(image.ImageBase + frame.Trailer, frame.HeaderLength)));
            json.WriteNumber("flags", frame.Flags);
            json.WriteString("kind", (frame.Flags & 3) switch { 0 => "root", 1 => "handler", _ => "filter" });
            json.WriteBoolean("reverse_pinvoke", (frame.Flags & 8) != 0);
            json.WriteNumber("associated_data", frame.AssociatedData);
            json.WriteNumber("associated_flags", frame.AssociatedFlags);
            json.WriteNumber("unboxing_target", frame.UnboxingTarget);
            json.WriteNumber("exception_info", frame.ExceptionInfo == 0 ? 0 : managed.Exceptions[frame.ExceptionInfo - 1].Address);
            json.WriteEndObject();
        }
        json.WriteEndArray();

        json.WriteStartArray("exceptions");
        foreach (ref readonly var blob in managed.Exceptions.AsSpan()) {
            json.WriteStartObject();
            json.WriteNumber("rva", blob.Address);
            json.WriteNumber("length", blob.Length);
            json.WriteString("bytes", Convert.ToHexStringLower(image.FileSpan(image.ImageBase + blob.Address, checked((int)blob.Length))));
            json.WriteStartArray("clauses");
            foreach (ref readonly var clause in managed.Clauses.AsSpan(blob.Clauses.Start, blob.Clauses.Count)) {
                json.WriteStartObject();
                json.WriteNumber("rva", clause.Address);
                json.WriteString("kind", clause.Kind switch {
                    ExceptionClauseKind.Typed => "typed",
                    ExceptionClauseKind.Fault => "fault",
                    ExceptionClauseKind.Filter => "filter",
                    _ => "marker"
                });
                json.WriteNumber("try_start", clause.TryStart);
                json.WriteNumber("try_end", clause.TryEnd);
                json.WriteNumber("handler_offset", clause.HandlerOffset);
                json.WriteNumber("handler_cell", clause.HandlerCell);
                json.WriteNumber("filter_offset", clause.FilterOffset);
                json.WriteNumber("filter_cell", clause.FilterCell);
                json.WriteNumber("type_rva", clause.Type);
                json.WriteNumber("type_cell", clause.TypeCell);
                json.WriteEndObject();
            }
            json.WriteEndArray();
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteEndObject();
    }
}
