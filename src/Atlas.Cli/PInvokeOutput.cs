using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class PInvokeOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, Extraction extraction) {
        var image = extraction.Image;
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("image_base", image.ImageBase);
        json.WriteString("source", "MethodFixupCell::ModuleFixupCell::TypeMap::<Module>");
        json.WriteStartArray("modules");
        foreach (ref readonly var module in CollectionsMarshal.AsSpan(extraction.PInvokes.Modules)) {
            json.WriteStartObject();
            json.WriteNumber("address", module.Address);
            json.WriteNumber("name_address", module.NameAddress);
            json.WriteString("module", image.FileData.AsSpan(module.Name.Start, module.Name.Count));
            json.WriteNumber("calling_assembly_type", module.CallingAssemblyType);
            json.WriteNumber("search_path", module.SearchPath);
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteStartArray("methods");
        foreach (ref readonly var method in CollectionsMarshal.AsSpan(extraction.PInvokes.Methods)) {
            json.WriteStartObject();
            json.WriteNumber("address", method.Address);
            json.WriteNumber("entry_point", method.EntryPoint);
            json.WriteNumber("module_index", method.Module);
            json.WriteNumber("flags", method.Flags);
            if (method.ByOrdinal)
                json.WriteNumber("ordinal", method.EntryPoint);
            else
                json.WriteString("name", image.FileData.AsSpan(method.Name.Start, method.Name.Count));
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteEndObject();
    }
}
