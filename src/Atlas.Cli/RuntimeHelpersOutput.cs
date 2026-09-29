using System.Text.Json;
using Atlas;

internal static class RuntimeHelpersOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, RuntimeHelpers helpers) {
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteString("status", helpers.Status.ToString());
        json.WriteString("evidence", "bootstrap::module_registration+os_registration+array_helper");
        json.WriteNumber("module_array", helpers.ModuleArray);
        json.WriteNumber("classlib_table", helpers.Table);
        json.WriteNumber("table_count", helpers.TableCount);
        json.WriteNumber("registration", helpers.Registration);
        json.WriteNumber("initialize_modules", helpers.InitializeModules);
        json.WriteNumber("array_type", helpers.ArrayType);
        json.WriteStartArray("helpers");
        foreach (var helper in helpers.Helpers) {
            json.WriteStartObject();
            json.WriteString("role", helper.Role);
            json.WriteNumber("address", helper.Address);
            json.WriteNumber("cell", helper.Cell);
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteStartArray("startup_path");
        foreach (var edge in helpers.StartupPath) {
            json.WriteStartArray();
            json.WriteNumberValue(edge.Instruction);
            json.WriteNumberValue(edge.Target);
            json.WriteEndArray();
        }
        json.WriteEndArray();
        json.WriteEndObject();
    }
}
