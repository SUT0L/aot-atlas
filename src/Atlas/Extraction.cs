using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Atlas;

public sealed class Extraction {
    public readonly PeImage Image;
    public readonly ReadyToRun Header;
    public readonly Metadata Metadata;
    public readonly ReflectionMaps Maps;
    public readonly ulong[] CommonFixups, NativeReferences, NativeStatics;
    public readonly HydratedRegion Hydrated;
    public readonly RuntimeMemory Memory;

    public readonly NativeLayout Layout;
    public readonly GenericMaps Generics = new();
    public readonly GvmTables Gvms = new();
    public readonly Marshalling Marshalling = new();
    public readonly VirtualMap Virtuals = new();
    public readonly TemplateMaps Templates = new();
    public readonly GenericDictionaries Dictionaries = new();
    public readonly TraceMaps Traces;
    public readonly StaticStorage Statics;
    public readonly FrozenObjects Frozen;
    public readonly ResourceMap Resources;
    public readonly PeLinkage Linkage;
    public readonly PInvokeFixups PInvokes;
    public readonly Enumerations Enums;
    public readonly UnwindTables Unwind;
    public readonly PeDebug Debug;
    public readonly ManagedUnwind Managed;

    public readonly MethodTables Types = new();
    public readonly GcLayouts Gc = new();
    public readonly RuntimeNames Names;
    public readonly FieldLayouts Fields;
    public readonly SharedMethods Shared;
    public readonly Dispatch Dispatch;
    public readonly double TypesSeconds, DispatchSeconds, FrozenSeconds;

    public Extraction(PeImage image, ReadyToRun rtr, Metadata metadata, ReflectionMaps maps, ulong[] commonFixups) {
        Image = image;
        Header = rtr;
        Metadata = metadata;
        Maps = maps;
        CommonFixups = commonFixups;

        long start = Stopwatch.GetTimestamp();
        Unwind = new UnwindTables(image);
        Debug = new PeDebug(image);
        Managed = new ManagedUnwind(image, Unwind, Debug);
        Enums = new Enumerations(metadata);
        Linkage = new PeLinkage(image);
        Resources = new ResourceMap(image, rtr);
        Hydrated = Hydration.Read(image, rtr);
        Memory = new RuntimeMemory(image, Hydrated);
        NativeReferences = RuntimeTables.Fixups(image, rtr.Find(331));
        NativeStatics = RuntimeTables.Fixups(image, rtr.Find(333));
        var section = rtr.Find(330);
        Layout = new NativeLayout(section.Length == 0 ? default : image.FileMemory(section.Start, checked((int)section.Length)),
            NativeReferences, metadata.Signatures);

        Generics.Read(image, rtr, metadata, Layout, NativeReferences, maps.Format);
        Gvms.Read(image, rtr, metadata, Layout, commonFixups, maps.Format, Types);
        Marshalling.Read(image, rtr, commonFixups, Types);
        Virtuals.Read(image, rtr, metadata, Layout, commonFixups, maps.Format);
        Templates.Read(image, rtr, metadata, Layout, commonFixups, maps.Format);
        Dictionaries.Read(image, rtr, metadata, Layout, Templates, maps.Format);
        Traces = new TraceMaps(image, rtr, metadata, commonFixups);
        Statics = new StaticStorage(image, rtr, Memory, commonFixups, NativeReferences, NativeStatics);

        foreach (var entry in maps.Methods) {
            if (entry.Signature == 0)
                Layout.Method(entry.NativeSignatureOffset);
        }

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.Types))
            Types.Add(entry.MethodTable, TypeEvidence.TypeMap);

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.DerivedTypes))
            Types.Add(entry.MethodTable, TypeEvidence.DerivedMap);

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.Methods))
            Types.Add(entry.DeclaringType, TypeEvidence.InvokeMap);

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.Fields))
            Types.Add(entry.DeclaringType, TypeEvidence.FieldMap);

        foreach (ulong argument in CollectionsMarshal.AsSpan(maps.GenericArguments))
            Types.Add(argument, TypeEvidence.InvokeMap);

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(Generics.Types))
            Types.Add(entry.MethodTable, TypeEvidence.GenericMap);

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(Generics.Methods))
            Types.Add(entry.DeclaringType, TypeEvidence.GenericMethod);

        foreach (ulong argument in CollectionsMarshal.AsSpan(Generics.Arguments))
            Types.Add(argument, TypeEvidence.GenericMethod);

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(Virtuals.Entries))
            Types.Add(entry.DeclaringType, TypeEvidence.VirtualMethod);

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(Templates.Types))
            Types.Add(entry.MethodTable, TypeEvidence.TypeTemplate);

        foreach (ulong address in Layout.ExternalTypes.Keys)
            Types.Add(address, TypeEvidence.NativeSignature);

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(Statics.Constructors))
            Types.Add(entry.Type, TypeEvidence.StaticConstructor);

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(Statics.Generics))
            Types.Add(entry.Type, TypeEvidence.GenericStatics);

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(Statics.Allocations))
            Types.Add(entry.RelatedType, TypeEvidence.StaticAllocation);

        foreach (ref readonly var clause in Managed.Clauses.AsSpan()) {
            if (clause.Kind == ExceptionClauseKind.Typed)
                Types.Add(image.ImageBase + clause.Type, TypeEvidence.ExceptionHandling);
        }

        long frozenStart = Stopwatch.GetTimestamp();
        Frozen = new FrozenObjects(rtr.Find(206), Memory, Types);
        long frozenEnd = Stopwatch.GetTimestamp();
        Types.Read(image, rtr, Memory);
        Gc.Read(Types, Memory, rtr.Major < 10);
        long bindStart = Stopwatch.GetTimestamp();
        Frozen.Bind(Types, Gc);
        FrozenSeconds = Stopwatch.GetElapsedTime(frozenStart, frozenEnd).TotalSeconds + Stopwatch.GetElapsedTime(bindStart).TotalSeconds;
        Names = new RuntimeNames(Types, maps);
        PInvokes = new PInvokeFixups(image, Types, maps);
        Layout.BindTypes(Types, Names);
        Gvms.Bind(Types, metadata.Signatures);
        Marshalling.Bind(Types, metadata, maps, rtr.Major < 10);
        Statics.BindFields(image, Memory, maps, Types);
        Fields = new FieldLayouts(metadata, maps, Types);
        Shared = new SharedMethods(this);
        Dictionaries.Bind(this);
        Enums.Bind(maps, Types, Fields.Bindings);
        long typesEnd = Stopwatch.GetTimestamp();
        TypesSeconds = Stopwatch.GetElapsedTime(start, typesEnd).TotalSeconds;

        Dispatch = new Dispatch(image, Memory, Types);
        Virtuals.Bind(image, Memory, Types, Dispatch);
        DispatchSeconds = Stopwatch.GetElapsedTime(typesEnd).TotalSeconds;
    }
}
