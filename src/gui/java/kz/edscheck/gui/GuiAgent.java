package kz.edscheck.gui;

import java.lang.instrument.Instrumentation;

public final class GuiAgent {
    private static Instrumentation instrumentation;

    private GuiAgent() {
    }

    public static void premain(String agentArgs, Instrumentation inst) {
        instrumentation = inst;
    }

    public static Instrumentation instrumentation() {
        return instrumentation;
    }
}
