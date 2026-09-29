using System.Buffers.Binary;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Atlas;

internal static class DictionarySlotChecks {
    internal static void Relationships(ReadOnlySpan<string> binaries) {
        foreach (string binary in binaries) {
            var image = new PeImage(File.ReadAllBytes(binary));
            var header = ReadyToRun.Read(image);
            var section = header.Find(313);
            var metadata = new Metadata(image.FileMemory(section.Start, checked((int)section.Length)),
                header.MetadataHandleBits, header.Major < 10);
            metadata.ReadDefinitions();
            var fixups = RuntimeTables.Fixups(image, header.Find(308));
            var maps = new ReflectionMaps();
            maps.Read(image, header, metadata, fixups, MapFormat.Auto);
            var extraction = new Extraction(image, header, metadata, maps, fixups);
            var dictionaries = extraction.Dictionaries;
            string[] lines = Invoke(binary).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            Assert(lines.Length == 20, "The relationship fixture must expose five operations over four concrete type arguments.");
            var observations = new Dictionary<(string Name, ulong Argument), DictionaryInstance>();
            var storageTypes = new HashSet<ulong>();
            var storageByArgument = new Dictionary<ulong, ulong>();
            var contracts = new Dictionary<ulong, ulong>();
            foreach (string line in lines) {
                string[] parts = line.Split('|');
                Assert(parts.Length == (parts[0] == "Interface" ? 6 : 5), "A live dictionary relationship has an unexpected shape.");
                ulong argument = image.ImageBase + Convert.ToUInt64(parts[1], 16);
                ulong dictionary = image.ImageBase + Convert.ToUInt64(parts[2], 16);
                ulong storage = image.ImageBase + Convert.ToUInt64(parts[4], 16);
                int index = dictionaries.Instances.FindIndex(instance => instance.Address == dictionary);
                Assert(index >= 0, "A live dictionary has no extracted recipe binding.");
                var instance = dictionaries.Instances[index];
                var method = extraction.Generics.Methods[instance.Method];
                Assert(method.Name == parts[0] && method.Arguments.Count == 1
                    && extraction.Generics.Arguments[method.Arguments.Start] == argument,
                    "The recipe context disagrees with the live generic method identity.");
                observations.Add((parts[0], argument), instance);
                storageTypes.Add(storage);
                if (!storageByArgument.TryAdd(argument, storage))
                    Assert(storageByArgument[argument] == storage, "A concrete argument has inconsistent runtime storage identities.");
                if (parts[0] == "Interface")
                    contracts.Add(argument, image.ImageBase + Convert.ToUInt64(parts[5], 16));
            }
            Assert(storageTypes.Count == 4, "Every concrete argument needs its own static storage identity.");

            int typeHandles = 0, nestedMethods = 0, gcCells = 0, nonGcBases = 0, interfaceCells = 0;
            foreach (var entry in observations) {
                var instance = entry.Value;
                Assert(instance.Slots.Count == 1, "Each fixture method performs exactly one dictionary lookup.");
                var slot = dictionaries.Slots[instance.Slots.Start];
                var recipe = dictionaries.Recipes[slot.Recipe];
                Assert(slot.Status == DictionarySlotStatus.Verified, $"{entry.Key} lacks a verified relationship.");
                if (entry.Key.Name == "Inner") {
                    Assert(recipe.Kind == DictionaryFixup.TypeHandle && slot.Value == entry.Key.Argument,
                        "Inner<T> must load the exact live typeof(T) handle.");
                    ++typeHandles;
                } else if (entry.Key.Name == "Outer") {
                    var inner = observations[("Inner", entry.Key.Argument)];
                    Assert(recipe.Kind == DictionaryFixup.MethodDictionary && slot.Method == inner.Method + 1
                        && slot.Value == inner.Address, "Outer<T> must load the live Inner<T> dictionary.");
                    ++nestedMethods;
                } else if (entry.Key.Name == "Interface") {
                    Assert(recipe.Kind == DictionaryFixup.InterfaceCall && slot.Cell > 0
                        && extraction.Types.Types[slot.Type - 1].Address == contracts[entry.Key.Argument],
                        "The dictionary must carry the exact live IReadOnlyCollection<T> interface identity.");
                    var cell = dictionaries.InterfaceCells[slot.Cell - 1];
                    Assert(cell.Address == slot.Value && cell.InterfaceType == slot.Type - 1 && cell.Slot == 1,
                        "The dispatch cell must independently select IReadOnlyCollection<T>.get_Count.");
                    ++interfaceCells;
                } else {
                    Assert(recipe.Kind == DictionaryFixup.StaticData && slot.Type > 0
                        && extraction.Types.Types[slot.Type - 1].Address == storageByArgument[entry.Key.Argument],
                        "A static lookup must identify the corresponding live closed storage type.");
                    if (entry.Key.Name == "Gc") {
                        Assert(recipe.Number == 1, "Gc<T> must load the GC static cell.");
                        ++gcCells;
                    } else {
                        Assert(entry.Key.Name == "NonGc" && recipe.Number == 2, "NonGc<T> must load the non-GC base.");
                        ++nonGcBases;
                    }
                }
            }
            Assert(typeHandles == 4 && nestedMethods == 4 && gcCells == 4 && nonGcBases == 4 && interfaceCells == 4,
                "The fixture must cover all five relationships for reference and generic value arguments.");

            string audit = Path.GetTempFileName();
            try {
                using (var writer = new BinaryWriter(File.Create(audit))) {
                    writer.Write(SHA256.HashData(image.FileData));
                    writer.Write(observations.Count);
                    foreach (var entry in observations) {
                        var slot = dictionaries.Slots[entry.Value.Slots.Start];
                        writer.Write(checked((uint)(slot.Address - image.ImageBase)));
                        writer.Write(checked((uint)(slot.Value - image.ImageBase)));
                    }
                    foreach (ulong type in storageTypes.Order()) {
                        var storage = extraction.Statics.Generics.Find(item => item.Type == type);
                        Assert(storage.NonGcBase != 0 && storage.GcCell != 0, "The storage oracle needs both static bases.");
                        writer.Write(checked((uint)(type - image.ImageBase)));
                        writer.Write(checked((uint)(storage.NonGcBase - image.ImageBase)));
                        writer.Write(checked((uint)(storage.GcCell - image.ImageBase)));
                    }
                }
                string output = Invoke(binary, audit);
                Assert(output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)[^1] == "verified|20|4",
                    "Live slot values or real static field addresses disagreed with the extracted relationships.");
            } finally {
                File.Delete(audit);
            }

            int controls = 0;
            foreach (string name in new[] { "Outer", "Gc", "NonGc", "Interface" }) {
                var entry = observations.First(item => item.Key.Name == name);
                var slot = dictionaries.Slots[entry.Value.Slots.Start];
                Assert(MemoryMarshal.TryGetArray(extraction.Memory.ReadMemory(slot.Address, 8), out var storage),
                    "Fixture dictionary bytes must have writable test backing storage.");
                var bytes = storage.Array!.AsSpan(storage.Offset, 8);
                try {
                    foreach (ulong value in new[] { 0UL, image.ImageBase }) {
                        BinaryPrimitives.WriteUInt64LittleEndian(bytes, value);
                        var rebound = Rebind(extraction);
                        var actual = rebound.Slots.Find(item => item.Address == slot.Address);
                        var expected = value == 0 ? DictionarySlotStatus.Null
                            : entry.Key.Name is "Outer" or "Interface" ? DictionarySlotStatus.Unresolved : DictionarySlotStatus.Conflict;
                        Assert(actual.Status == expected && actual.Method == 0, "A changed target retained its old proven relationship.");
                        ++controls;
                    }
                } finally {
                    BinaryPrimitives.WriteUInt64LittleEndian(bytes, slot.Value);
                }
            }

            var dispatch = observations.First(item => item.Key.Name == "Interface").Value;
            var dispatchSlot = dictionaries.Slots[dispatch.Slots.Start];
            var originalRecipe = dictionaries.Recipes[dispatchSlot.Recipe];
            try {
                var changed = originalRecipe;
                changed.Number ^= 1;
                dictionaries.Recipes[dispatchSlot.Recipe] = changed;
                var wrongSlot = Rebind(extraction).Slots.Find(slot => slot.Address == dispatchSlot.Address);
                Assert(wrongSlot.Status == DictionarySlotStatus.Conflict && wrongSlot.Cell == 0,
                    "A dispatch cell cant corroborate a different interface slot.");

                changed = originalRecipe;
                changed.Type = dictionaries.Recipes.First(recipe => recipe.Kind == DictionaryFixup.TypeHandle).Type;
                dictionaries.Recipes[dispatchSlot.Recipe] = changed;
                var wrongContract = Rebind(extraction).Slots.Find(slot => slot.Address == dispatchSlot.Address);
                Assert(wrongContract.Status == DictionarySlotStatus.Conflict && wrongContract.Cell == 0,
                    "A dispatch cell cant corroborate a different interface contract.");
                controls += 2;
            } finally {
                dictionaries.Recipes[dispatchSlot.Recipe] = originalRecipe;
            }

            var outer = observations.First(item => item.Key.Name == "Outer").Value;
            var nested = dictionaries.Slots[outer.Slots.Start];
            int nestedIndex = nested.Method - 1;
            var originalMethod = extraction.Generics.Methods[nestedIndex];
            int duplicateIndex = extraction.Generics.Methods.FindIndex(method => method.Name == "NonGc");
            Assert(duplicateIndex >= 0 && duplicateIndex != nestedIndex,
                "The fixture needs a distinct method record for the duplicate-identity control.");
            var originalDuplicate = extraction.Generics.Methods[duplicateIndex];
            int originalTemplate = extraction.Shared.Templates[duplicateIndex];
            try {
                extraction.Generics.Methods[duplicateIndex] = originalMethod;
                extraction.Shared.Templates[duplicateIndex] = extraction.Shared.Templates[nestedIndex];
                var duplicate = Rebind(extraction).Slots.Find(slot => slot.Address == nested.Address);
                Assert(duplicate.Status == DictionarySlotStatus.Unresolved && duplicate.Method == 0,
                    "Multiple matching records must not choose an arbitrary dictionary identity.");
                extraction.Generics.Methods[duplicateIndex] = originalDuplicate;
                extraction.Shared.Templates[duplicateIndex] = originalTemplate;

                var unknown = originalMethod;
                unknown.MetadataOffset = 0;
                unknown.Signature = 0;
                extraction.Generics.Methods[nestedIndex] = unknown;
                var unresolved = Rebind(extraction).Slots.Find(slot => slot.Address == nested.Address);
                Assert(unresolved.Status == DictionarySlotStatus.Unresolved && unresolved.Method == 0,
                    "An unknown method signature cant corroborate a nested dictionary identity.");
            } finally {
                extraction.Generics.Methods[duplicateIndex] = originalDuplicate;
                extraction.Shared.Templates[duplicateIndex] = originalTemplate;
                extraction.Generics.Methods[nestedIndex] = originalMethod;
            }
            Console.WriteLine($"{Convert.ToHexStringLower(SHA256.HashData(image.FileData))}: 20 live slots, "
                + $"4 nested methods, 4 GC cells, 4 non-GC bases, 4 interface cells; {controls + 2} negative controls.");
        }
    }

    internal static void Run(ReadOnlySpan<string> binaries) {
        foreach (string binary in binaries) {
            var image = new PeImage(File.ReadAllBytes(binary));
            var header = ReadyToRun.Read(image);
            var section = header.Find(313);
            var metadata = new Metadata(image.FileMemory(section.Start, checked((int)section.Length)),
                header.MetadataHandleBits, header.Major < 10);
            metadata.ReadDefinitions();
            var fixups = RuntimeTables.Fixups(image, header.Find(308));
            var maps = new ReflectionMaps();
            maps.Read(image, header, metadata, fixups, MapFormat.Auto);
            var extraction = new Extraction(image, header, metadata, maps, fixups);
            var recovered = extraction.Dictionaries;
            using var process = Process.Start(new ProcessStartInfo(Path.GetFullPath(binary)) {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            })!;
            string runtime = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            Assert(process.ExitCode == 0, "The fixture's runtime typeof assertions failed.");
            string[] lines = runtime.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            Assert(lines.Length == 11, "The fixture must expose ten shared calls and one exact call.");
            int dictionaries = 0, slots = 0, hydrated = 0;

            foreach (string line in lines) {
                string[] parts = line.Split('|');
                Assert(parts.Length is 5 or 6, "A runtime observation has an unexpected shape.");
                ulong dictionaryRva = Convert.ToUInt64(parts[3], 16);
                if (dictionaryRva == 0)
                    continue;
                ulong dictionary = image.ImageBase + dictionaryRva;
                int recordIndex = extraction.Generics.Methods.FindIndex(method => method.Dictionary == dictionary);
                Assert(recordIndex >= 0 && extraction.Shared.Templates[recordIndex] > 0,
                    $"The runtime dictionary lacks a unique static template: {line}.");
                var method = extraction.Generics.Methods[recordIndex];
                int instanceIndex = recovered.Instances.FindIndex(instance => instance.Method == recordIndex);
                Assert(instanceIndex >= 0, $"The dictionary was not emitted: {line}.");
                var instance = recovered.Instances[instanceIndex];
                Assert(instance.Layout > 0 && instance.Template == extraction.Shared.Templates[recordIndex] - 1,
                    $"The dictionary lacks its proven template layout: {line}.");
                var layout = recovered.Layouts[instance.Layout - 1];
                Assert(layout.UnsupportedKind == 0 && layout.SlotCount == instance.Slots.Count,
                    $"The fixture reached an unsupported dictionary layout: {line}.");

                ulong owner = image.ImageBase + Convert.ToUInt64(parts[1], 16);
                ulong[] arguments = new ulong[parts.Length - 4];
                for (int i = 0; i < arguments.Length; ++i)
                    arguments[i] = image.ImageBase + Convert.ToUInt64(parts[i + 4], 16);
                Assert(method.DeclaringType == owner && CollectionsMarshal.AsSpan(extraction.Generics.Arguments)
                    .Slice(method.Arguments.Start, method.Arguments.Count).SequenceEqual(arguments),
                    $"The runtime owner or arguments disagree with the metadata map: {line}.");
                if (extraction.Memory.Regions[extraction.Memory.Find(dictionary)].Hydrated)
                    ++hydrated;

                for (int index = instance.Slots.Start; index < instance.Slots.End; ++index) {
                    var slot = recovered.Slots[index];
                    int number = index - instance.Slots.Start;
                    var recipe = recovered.Recipes[slot.Recipe];
                    Assert(recipe.Kind == DictionaryFixup.TypeHandle && slot.Status == DictionarySlotStatus.Verified && slot.Type > 0,
                        $"Dictionary {dictionaryRva:X} slot {number} was not verified as a TypeHandle.");
                    int resolved = extraction.Fields.Bindings.Resolve(recipe.Type, extraction.Types.Index[owner] + 1, arguments);
                    Assert(slot.Type == resolved && slot.Address == dictionary + (uint)number * 8UL,
                        $"Dictionary {dictionaryRva:X} slot {number} has the wrong identity or address.");
                    ulong expected = extraction.Types.Types[resolved - 1].Address;
                    ulong actual = BinaryPrimitives.ReadUInt64LittleEndian(extraction.Memory.Read(slot.Address, 8));
                    Assert(actual == expected && slot.Value == expected,
                        $"Dictionary {dictionaryRva:X} slot {number}: {actual:X} != {expected:X}.");
                    ++slots;
                }
                ++dictionaries;
            }

            Assert(dictionaries == 10 && slots == 15 && hydrated == 10,
                $"Unexpected fixture coverage: {dictionaries} dictionaries, {slots} slots, {hydrated} hydrated.");

            int nullControls = 0, conflictControls = 0;
            foreach (var kind in new[] { DictionaryFixup.TypeHandle, DictionaryFixup.MethodDictionary, DictionaryFixup.StaticData }) {
                int index = recovered.Slots.FindIndex(slot => slot.Status == DictionarySlotStatus.Verified
                    && recovered.Recipes[slot.Recipe].Kind == kind);
                if (index < 0)
                    continue;
                var original = recovered.Slots[index];
                Assert(MemoryMarshal.TryGetArray(extraction.Memory.ReadMemory(original.Address, 8), out var storage),
                    "Fixture dictionary bytes must be backed by their input or hydration array.");
                var bytes = storage.Array!.AsSpan(storage.Offset, 8);
                try {
                    foreach (ulong value in new[] { 0UL, image.ImageBase }) {
                        BinaryPrimitives.WriteUInt64LittleEndian(bytes, value);
                        var rebound = Rebind(extraction);
                        var actual = rebound.Slots[index];
                        var expected = value == 0 ? DictionarySlotStatus.Null
                            : kind == DictionaryFixup.MethodDictionary ? DictionarySlotStatus.Unresolved : DictionarySlotStatus.Conflict;
                        Assert(actual.Status == expected && actual.Method == 0,
                            $"A changed {kind} target retained a verified relationship.");
                        if (value == 0)
                            ++nullControls;
                        else
                            ++conflictControls;
                    }
                } finally {
                    BinaryPrimitives.WriteUInt64LittleEndian(bytes, original.Value);
                }
            }

            int layoutIndex = recovered.Layouts.FindIndex(layout => layout.SlotCount >= 2
                && layout.Recipes.Count == layout.SlotCount && recovered.Recipes[layout.Recipes.Start + 1].Kind == DictionaryFixup.TypeHandle);
            Assert(layoutIndex >= 0, "The fixture lacks a multi-slot layout for grammar controls.");
            int templateIndex = Array.IndexOf(recovered.MethodLayouts, layoutIndex + 1);
            Assert(templateIndex >= 0, "The grammar control must use a method template.");
            var templates = new TemplateMaps();
            templates.Methods.Add(extraction.Templates.Methods[templateIndex]);
            int signatureOffset = recovered.Recipes[recovered.Layouts[layoutIndex].Recipes.Start + 1].Offset;
            ulong signatureAddress = header.Find(330).Start + (uint)signatureOffset;
            Assert(MemoryMarshal.TryGetArray(image.FileMemory(signatureAddress, 1), out var encoded),
                "NativeLayout must be backed by the fixture image.");
            byte originalKind = encoded.Array![encoded.Offset];
            try {
                encoded.Array[encoded.Offset] = 0xfc;
                var incomplete = new GenericDictionaries();
                incomplete.Read(image, header, metadata, extraction.Layout, templates, maps.Format);
                Assert(incomplete.Layouts.Count == 1 && incomplete.Layouts[0].Recipes.Count == 1
                    && incomplete.Layouts[0].UnsupportedKind == 0x7e,
                    "An unknown dictionary grammar must preserve its prefix and stop before subsequent slots.");

                encoded.Array[encoded.Offset] = 0;
                bool rejected = false;
                try {
                    new GenericDictionaries().Read(image, header, metadata, extraction.Layout, templates, maps.Format);
                } catch (InvalidDataException) {
                    rejected = true;
                }
                Assert(rejected, "The runtime-reserved null fixup kind must be rejected.");
            } finally {
                encoded.Array[encoded.Offset] = originalKind;
            }
            Console.WriteLine($"{Convert.ToHexStringLower(SHA256.HashData(image.FileData))}: "
                + $"10 hydrated dictionaries, 15 TypeHandle slots agree with live typeof identities; "
                + $"{nullControls} null and {conflictControls} changed-target controls, 2 grammar controls.");
        }
    }

    private static GenericDictionaries Rebind(Extraction extraction) {
        var source = extraction.Dictionaries;
        var result = new GenericDictionaries { MethodLayouts = source.MethodLayouts };
        result.Layouts.AddRange(source.Layouts);
        result.Recipes.AddRange(source.Recipes);
        result.Bind(extraction);
        return result;
    }

    private static string Invoke(string binary, string? audit = null) {
        var start = new ProcessStartInfo(Path.GetFullPath(binary)) {
            RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
        };
        if (audit != null)
            start.ArgumentList.Add(audit);
        using var process = Process.Start(start)!;
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        Assert(process.ExitCode == 0, "The live dictionary fixture failed.");
        return output;
    }

    private static void Assert([DoesNotReturnIf(false)] bool condition, string message) {
        if (!condition)
            throw new InvalidDataException(message);
    }
}
