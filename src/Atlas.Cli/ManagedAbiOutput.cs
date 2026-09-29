using System.Text.Json;
using Atlas;

internal static class ManagedAbiOutput {
    internal static void Write(Utf8JsonWriter json, Extraction extraction, ManagedAbi abi, int index, bool unboxed = false) {
        ref readonly var method = ref abi.Methods[index];
        json.WriteStartObject(unboxed ? "unboxed_abi" : "abi");
        json.WriteString("convention", "windows_x64_managed");
        json.WriteString("status", method.Status switch {
            AbiStatus.Complete => "complete",
            AbiStatus.SharedTemplate => "shared_template",
            AbiStatus.NoEntrypoint => "no_entrypoint",
            AbiStatus.AsyncVariant => "async_variant",
            AbiStatus.UnmanagedConvention => "unmanaged_convention",
            AbiStatus.Varargs => "varargs",
            AbiStatus.UniversalCanonical => "universal_canonical",
            AbiStatus.UnknownType => "unknown_type",
            AbiStatus.GenericDefinition => "generic_definition",
            AbiStatus.HiddenRecord => "hidden_record",
            AbiStatus.TraceIdentity => "trace_identity",
            _ => "unknown"
        });

        if (method.Status == AbiStatus.TraceIdentity) {
            json.WriteString("source", "stack_trace_method_mapping");
            json.WriteString("scope", "retained_method_identity");
        }

        if (method.Status is AbiStatus.Complete or AbiStatus.SharedTemplate or AbiStatus.TraceIdentity) {
            json.WriteStartObject("return");
            Value(json, extraction, method.Return);
            string location = method.Return.Kind == AbiKind.Void ? "none"
                : method.Return.Indirect ? Location(method.ReturnSlot, false)
                : method.Return.Kind == AbiKind.Float ? "xmm0" : "rax";
            json.WriteString("location", location);
            if (method.Return.Indirect)
                json.WriteString("returned_pointer", "rax");
            json.WriteEndObject();

            json.WriteStartArray("parameters");
            foreach (ref readonly var parameter in abi.Parameters.AsSpan(method.Parameters.Start, method.Parameters.Count)) {
                json.WriteStartObject();
                var value = parameter.Value;
                if (unboxed && parameter.Role == AbiRole.This)
                    value.Kind = AbiKind.ByReference;
                Value(json, extraction, value);
                json.WriteString("role", parameter.Role switch {
                    AbiRole.This => "this",
                    AbiRole.GenericContext => "generic_context",
                    _ => "parameter"
                });
                json.WriteString("location", Location(parameter.Slot, parameter.Value.Kind == AbiKind.Float));
                json.WriteEndObject();
            }
            json.WriteEndArray();
        }

        json.WriteEndObject();
    }

    private static string Location(int slot, bool floating) => slot >= 4 ? $"stack+{8 + 8 * slot}"
        : floating ? slot switch { 0 => "xmm0", 1 => "xmm1", 2 => "xmm2", _ => "xmm3" }
        : slot switch { 0 => "rcx", 1 => "rdx", 2 => "r8", _ => "r9" };

    private static void Value(Utf8JsonWriter json, Extraction extraction, in AbiValue value) {
        json.WriteNumber("runtime_type", value.Binding == 0 ? 0 : extraction.Types.Types[value.Binding - 1].Address);
        json.WriteString("kind", value.Kind switch {
            AbiKind.Void => "void",
            AbiKind.Integer => "integer",
            AbiKind.Float => "float",
            AbiKind.Value => "value",
            AbiKind.Reference => "reference",
            AbiKind.Pointer => "pointer",
            AbiKind.ByReference or AbiKind.UnboxedReference => "byref",
            AbiKind.FunctionPointer => "function_pointer",
            AbiKind.BoxedReference => "boxed_reference",
            AbiKind.Context => "context",
            _ => "unknown"
        });
        json.WriteNumber("size", value.Size);
        json.WriteBoolean("indirect", value.Indirect);
    }
}
