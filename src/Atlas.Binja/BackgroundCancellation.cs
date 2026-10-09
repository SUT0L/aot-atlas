namespace Atlas.Binja;

internal sealed class BackgroundCancellation : IDisposable {
    private readonly CancellationTokenSource source = new();
    private readonly Timer? timer;
    private readonly nint task;

    internal CancellationToken Token => source.Token;

    internal BackgroundCancellation(nint task) {
        this.task = task;

        if (task != 0) {
            Poll();
            timer = new Timer(static state => ((BackgroundCancellation)state!).Poll(), this, 25, 25);
        }
    }

    private void Poll() {
        if (!source.IsCancellationRequested && Core.BNIsBackgroundTaskCancelled(task) != 0)
            source.Cancel();
    }

    public void Dispose() {
        // Wait for the final native cancellation query before the caller frees its task.
        if (timer is not null)
            timer.DisposeAsync().AsTask().GetAwaiter().GetResult();

        source.Dispose();
    }
}
