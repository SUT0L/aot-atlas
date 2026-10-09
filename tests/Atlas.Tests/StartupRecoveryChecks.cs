using System.Buffers.Binary;
using Atlas;

internal static class StartupRecoveryChecks {
    internal static void Run(byte[] managedFixture) {
        byte[] fixture = Create(managedFixture);
        var image = new PeImage(fixture);
        var unwind = new UnwindTables(image);
        var startup = Discover(image, unwind);

        Assert(startup.Status == RuntimeHelperStatus.Complete
            && startup.ManagedStart == 0x1010 && startup.ManagedLength == 0x90);
        Assert(startup.UnboxingStart == 0x1080 && startup.UnboxingLength == 0x20 && startup.TableCount == 14);

        var managed = new ManagedUnwind(image, unwind, null, startup);
        Assert(managed.RegionSource == ManagedRegionSource.Startup
            && managed.Frames.Length == 4 && managed.Clauses.Length == 3);
        Assert(managed.Frames[0].FrameCount == 3 && managed.Frames[3].UnboxingTarget == 0x1010);

        var oracleImage = new PeImage(managedFixture);
        var oracle = new ManagedUnwind(oracleImage, new UnwindTables(oracleImage), new PeDebug(oracleImage));
        Assert(managed.Frames.SequenceEqual(oracle.Frames)
            && managed.Clauses.SequenceEqual(oracle.Clauses)
            && managed.Exceptions.SequenceEqual(oracle.Exceptions));

        MemoryWrites(fixture, startup);

        foreach (int entryKind in new[] { 0, 1, 2, 3 }) {
            byte[] changed = (byte[])fixture.Clone();
            BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(104), 0x1800);
            int entryOffset = 0x1800 + 512 - 0x1000;
            changed[entryOffset] = entryKind == 0 ? (byte)0xE8 : (byte)0xE9;
            BinaryPrimitives.WriteInt32LittleEndian(changed.AsSpan(entryOffset + 1),
                (entryKind == 3 ? 0x1805 : 0x1100) - 0x1805);
            changed[entryOffset + 5] = 0xC3;

            if (entryKind < 2) {
                BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(228), 72);
                WriteFunction(changed, 5, 0x1800, 0x1806, 0x1380);
            } else if (entryKind == 3) {
                changed[entryOffset + 5] = 0xE9;
                BinaryPrimitives.WriteInt32LittleEndian(changed.AsSpan(entryOffset + 6), 0x1100 - 0x180A);
            }

            image = new PeImage(changed);
            var discovered = Discover(image, new UnwindTables(image));
            Assert(discovered.Status == RuntimeHelperStatus.Complete && discovered.ManagedStart == startup.ManagedStart);
            Assert(discovered.StartupPath.Length == (entryKind == 3 ? 2 : 1));
            Assert(discovered.StartupPath[0] == new CodeEdge(0x140001800,
                entryKind == 3 ? 0x140001805UL : 0x140001100UL));
        }

        // The byte prefilter may find LEA bytes inside an immediate; only decoded instructions are evidence.
        byte[] decoy = (byte[])fixture.Clone();
        int decoyOffset = 0x1800 + 512 - 0x1000;
        decoy[decoyOffset] = 0x48;
        decoy[decoyOffset + 1] = 0xB8;
        decoy[decoyOffset + 2] = 0x8D;
        decoy[decoyOffset + 3] = 0x05;
        BinaryPrimitives.WriteInt32LittleEndian(decoy.AsSpan(decoyOffset + 4), 0x2000 - 0x1808);
        decoy[decoyOffset + 10] = 0xC3;
        BinaryPrimitives.WriteUInt32LittleEndian(decoy.AsSpan(228), 72);
        WriteFunction(decoy, 5, 0x1800, 0x180B, 0x1380);

        image = new PeImage(decoy);
        Assert(Discover(image, new UnwindTables(image)).Status == RuntimeHelperStatus.Complete);

        foreach (bool registration in new[] { false, true }) {
            byte[] changed = (byte[])fixture.Clone();

            if (registration) {
                int body = 0x1100 + 512 - 0x1000;
                changed[body] = 0xE9;
                BinaryPrimitives.WriteInt32LittleEndian(changed.AsSpan(body + 1), 0x1194 - 0x1105);
            } else {
                int entry = 0x1800 + 512 - 0x1000;
                BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(104), 0x1800);
                BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(228), 72);
                WriteFunction(changed, 5, 0x1800, 0x180B, 0x1380);
                changed[entry] = 0xE9;
                BinaryPrimitives.WriteInt32LittleEndian(changed.AsSpan(entry + 1), 5);
                changed[entry + 5] = 0xE8;
                BinaryPrimitives.WriteInt32LittleEndian(changed.AsSpan(entry + 6), 0x1100 - 0x180A);
                changed[entry + 10] = 0xC3;
            }

            image = new PeImage(changed);
            var unreachable = Discover(image, new UnwindTables(image));
            Assert(unreachable.Status != RuntimeHelperStatus.Complete);
            Assert(unreachable.ManagedLength == 0 && unreachable.Helpers.Length == 0);
        }

        for (int fault = 0; fault < 9; ++fault) {
            byte[] changed = (byte[])fixture.Clone();

            switch (fault) {
                case 0: // The reserved classlib slot must remain empty.
                    BinaryPrimitives.WriteUInt64LittleEndian(changed.AsSpan(0x1080), 0x1400011A0);
                    break;

                case 1:
                    BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(104), 0);
                    break;

                case 2: // Slot five must return System.Array's EEType.
                    BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(0x10E0), 0);
                    break;

                case 3: // An indirect call invalidates the registration state.
                    changed[0x1100 + 512 - 0x1000 + 0x5D] = 0xFF;
                    changed[0x1100 + 512 - 0x1000 + 0x5E] = 0xD0;
                    break;

                case 5: // A cyclic leaf thunk does not prove reachability.
                    BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(104), 0x1800);
                    changed[0x1800 + 512 - 0x1000] = 0xE9;
                    BinaryPrimitives.WriteInt32LittleEndian(changed.AsSpan(0x1801 + 512 - 0x1000), -5);
                    break;

                case 6: // An indirect leaf thunk has no statically proven successor.
                    BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(104), 0x1800);
                    changed[0x1800 + 512 - 0x1000] = 0xFF;
                    changed[0x1801 + 512 - 0x1000] = 0x25;
                    break;

                case 8: // A jump into the registration body's middle does not prove its entry is reached.
                    BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(104), 0x1800);
                    changed[0x1800 + 512 - 0x1000] = 0xE9;
                    BinaryPrimitives.WriteInt32LittleEndian(changed.AsSpan(0x1801 + 512 - 0x1000), 0x1101 - 0x1805);
                    break;

                case 7:
                    BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(104), 0x1800);
                    changed[0x1800 + 512 - 0x1000] = 0xE9;
                    BinaryPrimitives.WriteInt32LittleEndian(changed.AsSpan(0x1801 + 512 - 0x1000), 0x2000 - 0x1805);
                    break;

                case 4:
                    AddStartup(changed, 0x1800);
                    BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(228), 72);
                    WriteFunction(changed, 5, 0x1800, 0x1895, 0x1380);
                    break;
            }

            image = new PeImage(changed);
            unwind = new UnwindTables(image);
            var rejected = Discover(image, unwind);

            Assert(rejected.Status == (fault == 4
                ? RuntimeHelperStatus.Ambiguous : RuntimeHelperStatus.UnsupportedStartup));
            Assert(rejected.ManagedLength == 0 && rejected.Helpers.Length == 0);

            managed = new ManagedUnwind(image, unwind, null, rejected);
            Assert(managed.RegionSource == ManagedRegionSource.Unknown && managed.Frames.Length == 0);
        }

        Console.WriteLine("Startup recovery: compiled bootstrap SHR, linker-range EH equivalence, unboxing links, reserved slots, Array identity, indirect calls, call/tailcall entry paths, leaf thunk chains/cycles, embedded decoys and ambiguity passed.");
    }

    private static RuntimeHelpers Discover(PeImage image, UnwindTables unwind) {
        var header = ReadyToRun.Read(image);

        return new RuntimeHelpers(image, header, new RuntimeMemory(image, default), unwind);
    }

    private static void MemoryWrites(byte[] fixture, RuntimeHelpers startup) {
        Assert(Check(0, []) == RuntimeHelperStatus.Complete);
        Assert(Check(0, [0x48, 0x89, 0x44, 0x24, 0xF8]) == RuntimeHelperStatus.Complete);

        foreach (byte segment in new byte[] { 0x64, 0x65 })
            Assert(Check(segment, []) != RuntimeHelperStatus.Complete);

        foreach (byte[] clobber in new[] {
            new byte[] { 0x0F, 0xAE, 0x24, 0x24 },
            new byte[] { 0x48, 0x89, 0xE7, 0xB9, 64, 0, 0, 0, 0xF3, 0xAA },
            new byte[] { 0x65, 0x48, 0x89, 0x44, 0x24, 40 }
        })
            Assert(Check(0, clobber) != RuntimeHelperStatus.Complete);

        RuntimeHelperStatus Check(byte segment, byte[] clobber) {
            const int begin = 0x1100;
            const int file = begin + 512 - 0x1000;
            const int length = 0x95;
            var code = new List<byte>();
            code.AddRange(Load(0x48, 0xBA, 0x140000000UL + startup.ManagedStart));
            code.AddRange(Load(0x49, 0xB8, startup.ManagedLength));
            code.AddRange(Load(0x49, 0xB9, 0x140000000UL + startup.UnboxingStart));
            code.AddRange(Store(32, startup.UnboxingLength));
            code.AddRange(Load(0x48, 0xB8, startup.Table));

            if (segment != 0)
                code.Add(segment);

            code.AddRange([0x48, 0x89, 0x44, 0x24, 40]);
            code.AddRange(Store(48, (uint)startup.TableCount));
            code.AddRange(clobber);
            Call(startup.InitializeModules);

            byte[] modules = [0x48, 0x8D, 0x15, 0, 0, 0, 0];
            BinaryPrimitives.WriteInt32LittleEndian(modules.AsSpan(3),
                checked((int)((long)startup.ModuleArray - 0x140000000L - begin - code.Count - 7)));
            code.AddRange(modules);
            code.AddRange(Load(0x49, 0xB8, 2));
            code.AddRange(Load(0x49, 0xB9, startup.Table));
            code.AddRange(Store(32, (uint)startup.TableCount));
            Call(startup.InitializeModules);
            code.Add(0xC3);
            Assert(code.Count <= length);

            byte[] changed = (byte[])fixture.Clone();
            changed.AsSpan(file, length).Fill(0x90);
            code.ToArray().CopyTo(changed, file);

            var image = new PeImage(changed);
            return Discover(image, new UnwindTables(image)).Status;

            void Call(ulong target) {
                byte[] bytes = [0xE8, 0, 0, 0, 0];
                BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(1),
                    checked((int)((long)target - 0x140000000L - begin - code.Count - 5)));
                code.AddRange(bytes);
            }
        }

        static byte[] Load(byte rex, byte opcode, ulong value) {
            byte[] bytes = [rex, opcode, 0, 0, 0, 0, 0, 0, 0, 0];
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(2), value);

            return bytes;
        }

        static byte[] Store(byte offset, uint value) {
            byte[] bytes = [0x48, 0xC7, 0x44, 0x24, offset, 0, 0, 0, 0];
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(5), value);

            return bytes;
        }
    }

    private static byte[] Create(byte[] managedFixture) {
        byte[] bytes = new byte[0x1200];
        managedFixture.CopyTo(bytes, 0);
        bytes.AsSpan(248, 8).Clear();
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(70), 2);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(104), 0x1100);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(144), 0x3000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(228), 60);

        ".rdata"u8.CopyTo(bytes.AsSpan(368));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(376), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(380), 0x2000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(384), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(388), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(404), 0x40000040);

        WriteFunction(bytes, 4, 0x1100, 0x1195, 0x1380);
        bytes[0x1380 + 512 - 0x1000] = 1;
        AddStartup(bytes, 0x1100);
        bytes[0x11A0 + 512 - 0x1000] = 0xC3;
        new byte[] { 0x48, 0x8D, 0x05, 0, 0, 0, 0, 0xC3 }
            .CopyTo(bytes, 0x11B0 + 512 - 0x1000);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(0x11B3 + 512 - 0x1000), 0x20E0 - 0x11B7);

        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x1008), 0x140002020);
        "RTR\0"u8.CopyTo(bytes.AsSpan(0x1020));
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x1024), 10);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x1026), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x102C), 1);
        bytes[0x102E] = 24;
        bytes[0x102F] = 1;
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(0x1030), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x1038), 0x140002060);

        for (int slot = 0; slot < 14; ++slot) {
            if (slot is 2 or 4 or >= 10)
                continue;

            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x1060 + slot * 8),
                slot == 5 ? 0x1400011B0UL : 0x1400011A0UL);
        }

        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x10E0), 0x16U << 26);
        return bytes;
    }

    private static void WriteFunction(byte[] bytes, int index, uint begin, uint end, uint unwind) {
        var row = bytes.AsSpan(0x1200 + 512 - 0x1000 + index * 12);
        BinaryPrimitives.WriteUInt32LittleEndian(row, begin);
        BinaryPrimitives.WriteUInt32LittleEndian(row[4..], end);
        BinaryPrimitives.WriteUInt32LittleEndian(row[8..], unwind);
    }

    private static void AddStartup(byte[] bytes, int rva) {
        // clang-cl /O2 compilation of NativeAOT's two bootstrap registration calls; relocations below name the fixture operands.
        byte[] code = Convert.FromHexString("564883EC40488D0DF4FFFFFFE8870000004889C6488D05FD0F000048894424284C8D0D9C000000488D05A50000004429C889442420C74424300E000000488D155F0000004C8D05780000004129D04889F1E84600000089C1B8FFFFFFFF84C9742E488D15980F00004C8D05A10F00004929D049C1E803C74424200E0000004C8D0D930F00004889F1E81500000031C04883C4405EC3");
        (int Displacement, int Next, int Target)[] relocations = [
            (8, 0xC, rva), (0xD, 0x11, 0x11A0), (0x17, 0x1B, 0x2060), (0x23, 0x27, 0x1080),
            (0x2A, 0x2E, 0x10A0), (0x40, 0x44, 0x1010), (0x47, 0x4B, 0x10A0), (0x52, 0x56, 0x11A0),
            (0x64, 0x68, 0x2000), (0x6B, 0x6F, 0x2010), (0x81, 0x85, 0x2060), (0x89, 0x8D, 0x11A0)
        ];

        foreach (var relocation in relocations)
            BinaryPrimitives.WriteInt32LittleEndian(code.AsSpan(relocation.Displacement),
                relocation.Target - rva - relocation.Next);

        code.CopyTo(bytes, rva + 512 - 0x1000);
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Startup recovery assertion failed.");
    }
}
