package kz.edscheck.gui;

import kz.edscheck.app.RunResult;
import kz.edscheck.app.RunnerParams;
import kz.edscheck.trust.KalkanJarException;
import kz.edscheck.trust.LibraryJarException;

@FunctionalInterface
public interface RunnerInvoker {
    RunResult run(RunnerParams params) throws KalkanJarException, LibraryJarException;
}
