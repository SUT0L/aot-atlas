using System.Diagnostics;
using System.Runtime.InteropServices;
using Atlas;
using Atlas.Binja;

internal static unsafe class EnumChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        Assert(sizeof(NativeEnumMember) == 24);
        Span<double> samples = stackalloc double[5];
        foreach (string binary in binaries) {
            var image = new PeImage(File.ReadAllBytes(binary));
            var rtr = ReadyToRun.Read(image);
            var section = rtr.Find(313);
            var metadata = new Metadata(section.Length == 0 ? default : image.FileMemory(section.Start, checked((int)section.Length)),
                rtr.MetadataHandleBits, rtr.Major < 10);
            metadata.ReadDefinitions();
            var fixups = RuntimeTables.Fixups(image, rtr.Find(308));
            var maps = new ReflectionMaps();
            maps.Read(image, rtr, metadata, fixups, MapFormat.Auto);
            var extraction = new Extraction(image, rtr, metadata, maps, fixups);
            var enums = extraction.Enums;
            if (Path.GetFileNameWithoutExtension(binary) == "MetadataCollisionProbe") {
                var collisions = enums.Definitions.Where(entry => metadata.Types[entry.MetadataType].Name.EndsWith("]Collision.Choice", StringComparison.Ordinal)).ToArray();
                Assert(collisions.Length == 2 && collisions[0].Signature != collisions[1].Signature);
                Assert(collisions.All(entry => entry.Members.Count == 1));
                var values = collisions.Select(entry => enums.Members[entry.Members.Start].Bits).Order().ToArray();
                Assert(values.AsSpan().SequenceEqual([1UL, 2UL]));
            }

            nint[] types = new nint[enums.Definitions.Count];
            EnumTypes.Create(metadata, enums, types);

            for (int i = 0; i < types.Length; ++i) {
                var definition = enums.Definitions[i];
                if (definition.Width == 0) {
                    Assert(types[i] == 0);
                    continue;
                }

                // Release the original handle before inspecting its retained copy
                nint retained = Core.BNNewTypeReference(types[i]);
                Core.BNFreeType(types[i]);
                types[i] = retained;
                Assert(Inspect.BNGetTypeClass(retained) == 5);
                Assert(Core.BNGetTypeWidth(retained) == definition.Width);
                var signed = Inspect.BNIsTypeSigned(retained);
                Assert(signed.Value == (definition.Signed ? 1 : 0) && signed.Confidence == 255);
                nint enumeration = Inspect.BNGetTypeEnumeration(retained);
                nuint count = 0;
                var members = Inspect.BNGetEnumerationMembers(enumeration, &count);
                Assert(count == (nuint)definition.Members.Count);
                for (int j = 0; j < (int)count; ++j) {
                    var expected = enums.Members[definition.Members.Start + j];
                    Assert(Marshal.PtrToStringUTF8((nint)members[j].Name) == metadata.Fields[expected.Field].Name);
                    ulong bits = members[j].Value & (ulong.MaxValue >> (64 - definition.Width * 8));
                    Assert(bits == expected.Bits && members[j].IsDefault == 0);
                    if (definition.Signed && (bits & (1UL << (definition.Width * 8 - 1))) != 0)
                        Assert(unchecked((long)members[j].Value) < 0);
                }
                Inspect.BNFreeEnumerationMemberList(members, count);
                Core.BNFreeEnumeration(enumeration);
                Core.BNFreeType(retained);
                types[i] = 0;
            }

            for (int sample = 0; sample < samples.Length; ++sample) {
                long start = Stopwatch.GetTimestamp();
                EnumTypes.Create(metadata, enums, types);
                samples[sample] = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
                foreach (nint type in types) {
                    if (type != 0)
                        Core.BNFreeType(type);
                }
                types.AsSpan().Clear();
            }
            samples.Sort();
            Console.WriteLine($"BN6 enums: {enums.Definitions.Count} definitions, {enums.Members.Count} constants, {samples[2]:F3} ms native construction; {Path.GetFileName(binary)}.");
        }
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Binary Ninja's native enum disagrees with its metadata definition.");
    }
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeEnumMember {
    internal byte* Name;
    internal ulong Value;
    internal byte IsDefault;
}

internal static unsafe partial class Inspect {
    [LibraryImport("binaryninjacore")] internal static partial BoolConfidence BNIsTypeSigned(nint type);
    [LibraryImport("binaryninjacore")] internal static partial nint BNGetTypeEnumeration(nint type);
    [LibraryImport("binaryninjacore")] internal static partial NativeEnumMember* BNGetEnumerationMembers(nint enumeration, nuint* count);
    [LibraryImport("binaryninjacore")] internal static partial void BNFreeEnumerationMemberList(NativeEnumMember* members, nuint count);
}
