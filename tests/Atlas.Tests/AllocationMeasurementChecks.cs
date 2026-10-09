internal static class AllocationMeasurementChecks {
    private static byte[]? retained;

    internal static void Run() {
        int sum = 0;
        long empty;

        using (var measurement = new AllocationMeasurement()) {
            for (int value = 0; value < 1024; ++value)
                sum += value;

            empty = measurement.AllocatedBytes;
        }

        if (sum != 523776 || empty != 0)
            throw new Exception("Arithmetic-only measurement must preserve the exact zero-allocation counter.");

        long allocated;

        using (var measurement = new AllocationMeasurement()) {
            retained = new byte[64];
            allocated = measurement.AllocatedBytes;
        }

        if (retained is null || retained.Length != 64 || allocated <= 0)
            throw new Exception("Allocation isolation did not detect a retained heap allocation.");

        retained = null;
        Console.WriteLine("Allocation measurement: arithmetic-only work stays at zero and retained heap allocation remains observable.");
    }
}
