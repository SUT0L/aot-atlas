using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Atlas;

internal static class LinkageOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, PeImage image, PeLinkage linkage) {
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("image_base", image.ImageBase);
        json.WriteStartArray("import_modules");
        foreach (ref readonly var module in CollectionsMarshal.AsSpan(linkage.Modules)) {
            string moduleName = Encoding.ASCII.GetString(image.FileData.AsSpan(module.Name.Start, module.Name.Count));
            json.WriteStartObject();
            json.WriteString("module", moduleName);
            json.WriteNumber("descriptor", module.Descriptor);
            json.WriteNumber("lookup_table", module.Lookup);
            json.WriteNumber("address_table", module.AddressTable);
            json.WriteNumber("module_handle", module.Handle);
            json.WriteNumber("timestamp", module.Timestamp);
            json.WriteString("identity_source", module.IdentitySource.ToString());
            json.WriteBoolean("delay_loaded", module.DelayLoaded);
            json.WriteStartArray("imports");
            for (int i = module.Imports.Start; i < module.Imports.End; ++i) {
                ref readonly var entry = ref CollectionsMarshal.AsSpan(linkage.Imports)[i];
                string name = entry.Kind switch {
                    ImportKind.Name => Encoding.ASCII.GetString(image.FileData.AsSpan(entry.Name.Start, entry.Name.Count)),
                    ImportKind.Ordinal => $"#{entry.Ordinal}",
                    _ => $"??_iat_{entry.AddressCell:X}"
                };
                json.WriteStartObject();
                json.WriteString("name", $"import::{moduleName}!{name}");
                json.WriteString("kind", entry.Kind.ToString());
                json.WriteNumber("lookup_cell", entry.LookupCell);
                json.WriteNumber("address_cell", entry.AddressCell);
                json.WriteNumber("encoded_value", entry.EncodedValue);
                if (entry.Kind == ImportKind.Name) {
                    json.WriteString("import_name", name);
                    json.WriteNumber("hint", entry.Hint);
                } else if (entry.Kind == ImportKind.Ordinal) {
                    json.WriteNumber("ordinal", entry.Ordinal);
                }

                json.WriteEndObject();
            }
            json.WriteEndArray();
            json.WriteEndObject();
        }
        json.WriteEndArray();

        string exportModule = Encoding.ASCII.GetString(image.FileData.AsSpan(linkage.ExportModule.Start, linkage.ExportModule.Count));
        json.WriteString("export_module", exportModule);
        json.WriteStartArray("exports");
        foreach (ref readonly var entry in linkage.Exports.AsSpan()) {
            json.WriteStartObject();
            json.WriteString("name", $"export::{exportModule}!#{entry.Ordinal}");
            json.WriteNumber("ordinal", entry.Ordinal);
            json.WriteNumber("address_cell", entry.AddressCell);
            json.WriteNumber("rva", entry.Rva);
            json.WriteNumber("address", entry.Address);
            json.WriteString("kind", entry.Kind.ToString());
            if (entry.Kind == ExportKind.Forwarder)
                json.WriteString("forwarder", image.FileData.AsSpan(entry.Forwarder.Start, entry.Forwarder.Count));

            json.WriteStartArray("aliases");
            for (int i = entry.Names.Start; i < entry.Names.End; ++i) {
                ref readonly var alias = ref linkage.ExportNames[i];
                string name = Encoding.ASCII.GetString(image.FileData.AsSpan(alias.Name.Start, alias.Name.Count));
                json.WriteStartObject();
                json.WriteString("export_name", name);
                json.WriteString("name", $"export::{exportModule}!{name}");
                json.WriteNumber("pointer_cell", alias.PointerCell);
                json.WriteNumber("ordinal_cell", alias.OrdinalCell);
                json.WriteEndObject();
            }
            json.WriteEndArray();
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteEndObject();
    }
}
