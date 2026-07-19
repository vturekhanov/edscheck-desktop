package kz.edscheck.gui;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import kz.edscheck.app.RunResult;
import kz.edscheck.app.Runner;
import kz.edscheck.app.RunnerParams;

public final class CheckService {

    public static final long DEFAULT_TIMEOUT_SECONDS = 15;

    public sealed interface Result {
        record Success(RunResult result) implements Result {
        }

        record Failure(Throwable cause) implements Result {
        }

        record Timeout() implements Result {
        }
    }

    private final ExecutorService queueExecutor;
    private final RunnerInvoker runner;
    private final long timeoutSeconds;
    private ExecutorService runnerExecutor;

    public static CheckService forProduction() {
        return new CheckService(Executors.newSingleThreadExecutor(r -> daemonThread(r, "gui-queue")),
            Runner::run, DEFAULT_TIMEOUT_SECONDS);
    }

    public CheckService(ExecutorService queueExecutor, RunnerInvoker runner, long timeoutSeconds) {
        this.queueExecutor = queueExecutor;
        this.runner = runner;
        this.timeoutSeconds = timeoutSeconds;
        this.runnerExecutor = newRunnerExecutor();
    }

    public void submit(RunnerParams params, Consumer<Result> callback) {
        queueExecutor.execute(() -> callback.accept(runOne(params)));
    }

    private Result runOne(RunnerParams params) {
        Future<RunResult> future = runnerExecutor.submit(() -> runner.run(params));
        try {
            return new Result.Success(future.get(timeoutSeconds, TimeUnit.SECONDS));
        } catch (TimeoutException e) {
            future.cancel(true);
            runnerExecutor = newRunnerExecutor();
            return new Result.Timeout();
        } catch (ExecutionException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            return new Result.Failure(cause);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Result.Failure(e);
        }
    }

    private static ExecutorService newRunnerExecutor() {
        return Executors.newSingleThreadExecutor(r -> daemonThread(r, "gui-runner"));
    }

    private static Thread daemonThread(Runnable r, String name) {
        Thread t = new Thread(r, name);
        t.setDaemon(true);
        return t;
    }
}
