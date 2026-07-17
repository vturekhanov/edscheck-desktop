package kz.edscheck.gui.theme;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Supplier;


public final class ThemeWatcher {
    
    public static final long DEFAULT_POLL_INTERVAL_SECONDS = 3;

    private final Supplier<OsTheme> detector;
    private final Consumer<OsTheme> onChange;
    private final long pollIntervalSeconds;
    private volatile OsTheme last;
    private ScheduledExecutorService executor;

    public ThemeWatcher(Supplier<OsTheme> detector, Consumer<OsTheme> onChange, OsTheme initial) {
        this(detector, onChange, initial, DEFAULT_POLL_INTERVAL_SECONDS);
    }

    public ThemeWatcher(Supplier<OsTheme> detector, Consumer<OsTheme> onChange, OsTheme initial,
            long pollIntervalSeconds) {
        this.detector = detector;
        this.onChange = onChange;
        this.last = initial;
        this.pollIntervalSeconds = pollIntervalSeconds;
    }

    
    public synchronized void start() {
        if (executor != null) {
            return;
        }
        executor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "gui-theme-watcher");
            t.setDaemon(true);
            return t;
        });
        executor.scheduleAtFixedRate(
            this::pollOnce, pollIntervalSeconds, pollIntervalSeconds, TimeUnit.SECONDS);
    }

    public synchronized void stop() {
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
    }

    
    void pollOnce() {
        OsTheme current = detector.get();
        if (current != last) {
            onChange.accept(current);
            last = current;
        }
    }
}
