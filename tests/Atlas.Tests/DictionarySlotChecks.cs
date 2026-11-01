using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Atlas;

internal static class DictionarySlotChecks {
    internal static void Relationships(ReadOnlySpan<string> binaries) {
        foreach (string binary in binaries) {
            var image = new PeImage(File.ReadAllBytes(binary));
            var header = ReadyToRun.Read(image);

            var section = header.Find(313);
            var metadata = MetadataBuilder.FromImage(image, header);
            metadata.ReadDefinitions();

            var fixups = RuntimeTables.Fixups(image, header.Find(308));
            var maps = new ReflectionMaps();
            maps.Read(image, header, metadata, fixups, MapFormat.Auto);

            var extraction = new Extraction(image, header, metadata, maps, fixups);
            var dictionaries = extraction.Dictionaries;

            string[] lines = Invoke(binary).Split(
                '\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            Assert(lines.Length == 20,
                "The relationship fixture must expose five operations over four concrete type arguments.");

            var observations = new Dictionary<(string Name, ulong Argument), DictionaryInstance>();

            var storageTypes = new HashSet<ulong>();
            var storageByArgument = new Dictionary<ulong, ulong>();

            var contracts = new Dictionary<ulong, ulong>();

            foreach (string line in lines) {
                string[] parts = line.Split('|');
                Assert(parts.Length == (parts[0] == "Interface" ? 6 : 5),
                    "A live dictionary relationship has an unexpected shape.");

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
                    Assert(storageByArgument[argument] == storage,
                        "A concrete argument has inconsistent runtime storage identities.");

                if (parts[0] == "Interface")
                    contracts.Add(argument, image.ImageBase + Convert.ToUInt64(parts[5], 16));
            }

            Assert(storageTypes.Count == 4, "Every concrete argument needs its own static storage identity.");

            int typeHandles = 0;
            int nestedMethods = 0;
            int gcCells = 0;
            int nonGcBases = 0;
            int interfaceCells = 0;

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
                Assert(output.Split(
                    '\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)[^1] == "verified|20|4",
                    "Live slot values or real static field addresses disagreed with the extracted relationships.");
            } finally {
                File.Delete(audit);
            }

            Console.WriteLine($"{Convert.ToHexStringLower(SHA256.HashData(image.FileData))}: 20 live slots, "
                + "4 nested methods, 4 GC cells, 4 non-GC bases and 4 interface cells matched the running producer.");
        }
    }

    private static string Invoke(string binary, string? audit = null) {
        var start = new ProcessStartInfo(Path.GetFullPath(binary)) {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
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
