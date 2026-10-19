using System.Buffers;
using System.Runtime.InteropServices;
using System.Text;

namespace Atlas;

public enum CodeOriginKind : byte {
    Method,
    Unboxed,
    InvokeStub,
    Trace,
    Template,
    Constructor,
    ToNative,
    ToManaged,
    Cleanup,
    OpenDelegate,
    ClosedDelegate,
    CreateDelegate,
    Virtual,
    RuntimeRole,
    Export,
    InvalidExternalTypeMap,
    InvalidProxyTypeMap
}

public struct CodeOrigin {
    public ulong Address;
    public ulong Witness;

    public int Index;
    public int Aliases;

    public CodeOriginKind Kind;
    public IndexRange Name;
}

public sealed class CodeOrigins {
    internal readonly List<CodeOrigin> Values;
    internal ReadOnlyMemory<char> Text;
    public int NameCapacity { get; internal set; } = 128;

    public ReadOnlySpan<CodeOrigin> OriginEntries => CollectionsMarshal.AsSpan(Values);
    public ReadOnlySpan<char> NameText => Text.Span;

    public CodeOrigins() {
        Values = new();
    }

    public static string KindName(CodeOriginKind kind) => kind switch {
        CodeOriginKind.Method => "Method",
        CodeOriginKind.Unboxed => "Unboxed",
        CodeOriginKind.InvokeStub => "InvokeStub",
        CodeOriginKind.Trace => "Trace",
        CodeOriginKind.Template => "Template",
        CodeOriginKind.Constructor => "Constructor",
        CodeOriginKind.ToNative => "ToNative",
        CodeOriginKind.ToManaged => "ToManaged",
        CodeOriginKind.Cleanup => "Cleanup",
        CodeOriginKind.OpenDelegate => "OpenDelegate",
        CodeOriginKind.ClosedDelegate => "ClosedDelegate",
        CodeOriginKind.CreateDelegate => "CreateDelegate",
        CodeOriginKind.Virtual => "Virtual",
        CodeOriginKind.RuntimeRole => "RuntimeRole",
        CodeOriginKind.Export => "Export",
        CodeOriginKind.InvalidExternalTypeMap => "InvalidExternalTypeMap",
        CodeOriginKind.InvalidProxyTypeMap => "InvalidProxyTypeMap",
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    public CodeOrigins(Extraction extraction, ManagedAbi abi, RuntimeCode runtime) {
        if (!abi.IsFrom(extraction))
            throw new ArgumentException("The ABI belongs to a different extraction.", nameof(abi));

        int runtimeCount = abi.RuntimeCount;
        int capacity = checked(
            3 * runtimeCount
            + extraction.Traces.Methods.Count
            + extraction.Templates.Methods.Count
            + extraction.Statics.Constructors.Count
            + 3 * (extraction.Marshalling.Structs.Count + extraction.Marshalling.Delegates.Count)
            + extraction.Virtuals.Slots.Count
            + extraction.TypeMaps.ThrowingStubs.Length
            + runtime.Functions.Length
            + extraction.Linkage.Exports.Length);
        Values = new List<CodeOrigin>(capacity);

        Span<ulong> sections = stackalloc ulong[(int)RtrSectionId.ProxyTypeMap + 1];
        sections.Clear();

        foreach (var section in extraction.Header.Sections) {
            if ((uint)section.Id < sections.Length)
                sections[section.Id] = section.Start;
        }

        for (int i = 0; i < runtimeCount; ++i) {
            var record = new MethodRecord(extraction, i);
            ulong witness = sections[record.Section] + (uint)record.Vertex;

            if (record.Entrypoint != 0)
                Values.Add(new CodeOrigin {
                    Address = record.Entrypoint,
                    Witness = witness,
                    Index = i,
                    Kind = CodeOriginKind.Method,
                    Aliases = 1
                });

            if (record.InvokeStub != 0)
                Values.Add(new CodeOrigin {
                    Address = record.InvokeStub,
                    Witness = witness,
                    Index = i,
                    Kind = CodeOriginKind.InvokeStub,
                    Aliases = 1
                });

            if (abi.Methods[i].UnboxedTarget != 0)
                Values.Add(new CodeOrigin {
                    Address = abi.Methods[i].UnboxedTarget,
                    Witness = witness,
                    Index = i,
                    Kind = CodeOriginKind.Unboxed,
                    Aliases = 1
                });
        }

        for (int i = 0; i < extraction.Traces.Methods.Count; ++i) {
            var record = extraction.Traces.Methods[i];
            if (record.Entrypoint == 0)
                continue;

            Values.Add(new CodeOrigin {
                Address = record.Entrypoint,
                Witness = sections[(int)RtrSectionId.StackTraceMethodMapping] + (uint)record.Offset,
                Index = i,
                Kind = CodeOriginKind.Trace,
                Aliases = 1
            });
        }

        for (int i = 0; i < extraction.Templates.Methods.Count; ++i) {
            var record = extraction.Templates.Methods[i];
            if (record.Method.Entrypoint == 0)
                continue;

            Values.Add(new CodeOrigin {
                Address = record.Method.Entrypoint,
                Witness = sections[(int)RtrSectionId.GenericMethodsTemplateMap] + (uint)record.Vertex,
                Index = i,
                Kind = CodeOriginKind.Template,
                Aliases = 1
            });
        }

        for (int i = 0; i < extraction.Statics.Constructors.Count; ++i) {
            var record = extraction.Statics.Constructors[i];
            if (record.Entrypoint == 0)
                continue;

            Values.Add(new CodeOrigin {
                Address = record.Entrypoint,
                Witness = sections[(int)RtrSectionId.CctorContextMap] + (uint)record.Vertex,
                Index = i,
                Kind = CodeOriginKind.Constructor,
                Aliases = 1
            });
        }

        Span<ulong> targets = stackalloc ulong[3];

        for (int i = 0; i < extraction.Marshalling.Structs.Count + extraction.Marshalling.Delegates.Count; ++i) {
            int vertex;
            int index;
            int section;

            CodeOriginKind kind;

            if (i < extraction.Marshalling.Structs.Count) {
                var record = extraction.Marshalling.Structs[i];
                vertex = record.Vertex;
                index = i;
                section = (int)RtrSectionId.StructMarshallingStubMap;
                kind = CodeOriginKind.ToNative;

                targets[0] = record.ToNative;
                targets[1] = record.ToManaged;
                targets[2] = record.Cleanup;
            } else {
                index = i - extraction.Marshalling.Structs.Count;
                var record = extraction.Marshalling.Delegates[index];
                vertex = record.Vertex;
                section = (int)RtrSectionId.DelegateMarshallingStubMap;
                kind = CodeOriginKind.OpenDelegate;

                targets[0] = record.Open;
                targets[1] = record.Closed;
                targets[2] = record.Create;
            }

            for (int target = 0; target < targets.Length; ++target) {
                if (targets[target] == 0)
                    continue;

                Values.Add(new CodeOrigin {
                    Address = targets[target],
                    Witness = sections[section] + (uint)vertex,
                    Index = index,
                    Kind = (CodeOriginKind)((int)kind + target),
                    Aliases = 1
                });
            }
        }

        var throwingStubs = extraction.TypeMaps.ThrowingStubs;
        for (int i = 0; i < throwingStubs.Length; ++i) {
            ref readonly var stub = ref throwingStubs[i];
            ref readonly var group = ref stub.Map.Groups[stub.GroupIndex];
            Values.Add(new CodeOrigin {
                Address = group.ThrowingStub,
                Witness = stub.Map.Address + (uint)group.Vertex,
                Index = stub.GroupIndex,
                Kind = stub.Map.Kind == InteropTypeMapKind.External
                    ? CodeOriginKind.InvalidExternalTypeMap : CodeOriginKind.InvalidProxyTypeMap,
                Aliases = 1
            });
        }

        for (int i = 0; i < extraction.Virtuals.Slots.Count; ++i) {
            var slot = extraction.Virtuals.Slots[i];
            if (slot.Target == 0)
                continue;

            Values.Add(new CodeOrigin {
                Address = slot.Target,
                Witness = slot.TargetCell,
                Index = i,
                Kind = CodeOriginKind.Virtual,
                Aliases = 1
            });
        }

        for (int i = 0; i < runtime.Functions.Length; ++i) {
            var group = runtime.Functions[i];
            var role = runtime.Roles[group.Start];

            Values.Add(new CodeOrigin {
                Address = role.Target,
                Witness = role.Witness,
                Index = i,
                Kind = CodeOriginKind.RuntimeRole,
                Aliases = group.Count
            });
        }

        for (int i = 0; i < extraction.Linkage.Exports.Length; ++i) {
            var record = extraction.Linkage.Exports[i];
            if (record.Kind == ExportKind.Code)
                Values.Add(new CodeOrigin {
                    Address = record.Address,
                    Witness = record.AddressCell,
                    Index = i,
                    Kind = CodeOriginKind.Export,
                    Aliases = Math.Max(1, record.Names.Count)
                });
        }

        Values.Sort(static (left, right) => {
            int order = left.Address.CompareTo(right.Address);
            if (order == 0)
                order = ((byte)left.Kind).CompareTo((byte)right.Kind);

            return order != 0 ? order : left.Index.CompareTo(right.Index);
        });

        int count = 0;

        for (int first = 0; first < Values.Count;) {
            var selected = Values[first];
            int end = first + 1;

            while (end < Values.Count && Values[end].Address == selected.Address) {
                selected.Aliases = checked(selected.Aliases + Values[end].Aliases);
                ++end;
            }

            Values[count++] = selected;
            first = end;
        }

        Values.RemoveRange(count, Values.Count - count);
    }

    internal void Render(Extraction extraction, RuntimeCode runtime, ReadOnlySpan<bool> used) {
        int count = 0;

        foreach (bool value in used)
            count += value ? 1 : 0;

        var text = new ArrayBufferWriter<char>(Math.Max(1, checked(count * 128)));

        var renderer = new MethodText(extraction);

        var builder = new StringBuilder();
        char[] buffer = new char[Math.Max(4096, runtime.NameCapacity)];

        for (int i = 0; i < Values.Count; ++i) {
            if (!used[i])
                continue;

            ref var origin = ref CollectionsMarshal.AsSpan(Values)[i];

            builder.Clear();

            if (origin.Aliases > 1)
                builder.Append("shared_alias::");

            switch (origin.Kind) {
                case CodeOriginKind.Method:
                case CodeOriginKind.Unboxed:
                    if (origin.Kind == CodeOriginKind.Unboxed)
                        builder.Append("unboxed::");

                    builder.Append(renderer.Render(
                        new MethodRecord(extraction, origin.Index),
                        includeSignature: false));
                    break;

                case CodeOriginKind.InvokeStub:
                    builder.Append("invoke_stub::");
                    (origin.Address - extraction.Image.ImageBase).TryFormat(
                        buffer,
                        out int stubLength,
                        "X8");
                    builder.Append(buffer.AsSpan(0, stubLength));
                    break;

                case CodeOriginKind.Trace:
                    builder.Append(renderer.Render(
                        extraction.Traces.Methods[origin.Index],
                        includeSignature: false));
                    break;

                case CodeOriginKind.Template:
                    builder.Append(renderer.Render(
                        extraction.Templates.Methods[origin.Index],
                        includeSignature: false));
                    break;

                case CodeOriginKind.RuntimeRole:
                    var group = runtime.Functions[origin.Index];
                    int length = RuntimeCode.WriteName(extraction, runtime.Roles[group.Start], buffer);
                    builder.Append(buffer.AsSpan(0, length));
                    break;

                case CodeOriginKind.Virtual:
                    var method = extraction.Virtuals.Entries[origin.Index];
                    builder.Append(extraction.Names.Values[extraction.Types.Index[method.DeclaringType]])
                        .Append("::")
                        .Append(method.Identity.Name);
                    break;

                case CodeOriginKind.Export:
                    var export = extraction.Linkage.Exports[origin.Index];
                    builder.Append("export::");
                    if (export.Names.Count == 0) {
                        export.Ordinal.TryFormat(buffer, out int ordinalLength);
                        builder.Append('#').Append(buffer.AsSpan(0, ordinalLength));
                    } else {
                        var name = extraction.Linkage.ExportNames[export.Names.Start].Name;
                        if (name.Count > buffer.Length)
                            Array.Resize(ref buffer, name.Count);

                        int characters = Encoding.UTF8.GetChars(
                            extraction.Image.FileData.AsSpan(name.Start, name.Count),
                            buffer);
                        builder.Append(buffer.AsSpan(0, characters));
                    }
                    break;

                case CodeOriginKind.InvalidExternalTypeMap:
                case CodeOriginKind.InvalidProxyTypeMap:
                    var typeMap = origin.Kind == CodeOriginKind.InvalidExternalTypeMap
                        ? extraction.TypeMaps.External : extraction.TypeMaps.Proxy;

                    ref readonly var typeMapGroup = ref typeMap.Groups[origin.Index];
                    builder.Append(origin.Kind == CodeOriginKind.InvalidExternalTypeMap
                        ? "invalid_external_type_map::" : "invalid_proxy_type_map::");
                    builder.Append(extraction.Names.Values[extraction.Types.Index[typeMapGroup.GroupType]]);
                    break;

                default:
                    // A shared target can have conflicting owners
                    // Its selected record still supplies one explicit alias for navigation
                    int owner;
                    string prefix;

                    if (origin.Kind == CodeOriginKind.Constructor) {
                        owner = extraction.Types.Index[extraction.Statics.Constructors[origin.Index].Type];
                        prefix = "cctor::";
                    } else if (origin.Kind <= CodeOriginKind.Cleanup) {
                        owner = extraction.Marshalling.Structs[origin.Index].TypeIndex;
                        prefix = origin.Kind == CodeOriginKind.ToNative
                            ? "to_native::"
                            : origin.Kind == CodeOriginKind.ToManaged
                                ? "to_managed::"
                                : "cleanup::";
                    } else {
                        owner = extraction.Marshalling.Delegates[origin.Index].TypeIndex;
                        prefix = origin.Kind == CodeOriginKind.OpenDelegate
                            ? "open_delegate::"
                            : origin.Kind == CodeOriginKind.ClosedDelegate
                                ? "closed_delegate::"
                                : "create_delegate::";
                    }

                    builder.Append(prefix).Append(extraction.Names.Values[owner]);
                    break;
            }

            var destination = text.GetSpan(builder.Length);
            builder.CopyTo(0, destination, builder.Length);
            origin.Name = new IndexRange(text.WrittenCount, builder.Length);
            text.Advance(builder.Length);
            NameCapacity = Math.Max(NameCapacity, checked(builder.Length * 2 + 128));
        }

        Text = text.WrittenMemory;
    }
}
