using System.Text.Json;
using Atlas;

internal static class SectionsOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, PeImage image, ReadyToRun rtr) {
        json.WriteStartObject();
        json.WriteString("operation", "sections");
        json.WriteString("input_sha256", inputSha256);
        json.WriteString("representation", "initial_pe_image");
        json.WriteStartArray("sections");
        foreach (ref readonly var section in rtr.Sections.AsSpan()) {
            int fileOffset = 0, fileLength = 0;
            if (section.Start - image.ImageBase < image.HeaderSize) {
                fileOffset = (int)(section.Start - image.ImageBase);
                fileLength = (int)Math.Min(section.Length, image.HeaderSize - (ulong)fileOffset);
            } else {
                ref readonly var storage = ref image.Sections[image.FindSection(section.Start)];
                ulong offset = section.Start - image.ImageBase - storage.Rva;
                if (offset < (ulong)storage.FileSize) {
                    fileOffset = storage.FileOffset + (int)offset;
                    fileLength = (int)Math.Min(section.Length, (ulong)storage.FileSize - offset);
                }
            }

            json.WriteStartObject();
            json.WriteNumber("id", section.Id);
            json.WriteNumber("flags", section.Flags);
            json.WriteNumber("start", section.Start);
            json.WriteNumber("length", section.Length);
            // An old-format row without an end pointer names a location, not an empty allocation
            // The file cant establish its byte extent
            json.WriteString("extent", rtr.EntrySize == 16 || (section.Flags & 1) != 0 ? "range" : "start_only");
            json.WriteBase64String("file_bytes_base64", image.FileData.AsSpan(fileOffset, fileLength));
            json.WriteNumber("zero_fill_length", section.Length - (ulong)fileLength);
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteEndObject();
    }
}
