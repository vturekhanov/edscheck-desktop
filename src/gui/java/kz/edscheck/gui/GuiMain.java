package kz.edscheck.gui;

import java.awt.Desktop;
import java.awt.KeyboardFocusManager;
import java.awt.Window;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Path;
import java.util.List;

import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

import com.formdev.flatlaf.FlatLaf;

import kz.edscheck.gui.kalkan.KalkanFirstRunDialog;
import kz.edscheck.gui.kalkan.KalkanResolver;
import kz.edscheck.gui.msg.GuiMessages;
import kz.edscheck.gui.msg.GuiMsgKey;
import kz.edscheck.gui.theme.OsTheme;
import kz.edscheck.gui.theme.OsThemeDetector;
import kz.edscheck.gui.theme.ThemeApplier;
import kz.edscheck.gui.theme.ThemeWatcher;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.trust.LibraryJarException;
import kz.edscheck.trust.LibraryJars;

public final class GuiMain {
    private GuiMain() {
    }

    public static void main(String[] args) {
        Messages.setLocale(Messages.DEFAULT_LOCALE);
        GuiMessages.setLocale(GuiMessages.DEFAULT_LOCALE);
        System.setProperty("apple.awt.application.name", GuiMessages.get(GuiMsgKey.WINDOW_TITLE));

        try {
            LibraryJars.verifyRuntime(LibraryJars.resolveDirFromSystemProperty());
        } catch (LibraryJarException e) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR, e.getMessage()));
            System.exit(2);
        }

        OsTheme theme = OsThemeDetector.detect();
        ThemeApplier.apply(theme);

        if (Desktop.isDesktopSupported()) {
            Desktop desktop = Desktop.getDesktop();
            if (desktop.isSupported(Desktop.Action.APP_ABOUT)) {
                desktop.setAboutHandler(e -> showAboutDialog());
            }
        }

        resolveKalkan();

        ThemeWatcher themeWatcher = new ThemeWatcher(OsThemeDetector::detect, changed ->
            SwingUtilities.invokeLater(() -> {
                ThemeApplier.apply(changed);
                FlatLaf.updateUI();
            }), theme);
        themeWatcher.start();

        SwingUtilities.invokeLater(() -> new MainWindow().setVisible(true));
    }

    private static void resolveKalkan() {
        Instrumentation instrumentation = GuiAgent.instrumentation();
        KalkanResolver.Resolution resolution =
            KalkanResolver.resolve(instrumentation, KalkanResolver.defaultCandidates());
        if (resolution instanceof KalkanResolver.Resolution.AgentUnavailable) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR, GuiMessages.get(GuiMsgKey.KALKAN_AGENT_UNAVAILABLE)));
            System.exit(2);
            return;
        }
        while (resolution instanceof KalkanResolver.Resolution.NotFound) {
            Path resolvedPath = showFirstRunDialogAndAwaitResolution();
            resolution = KalkanResolver.resolve(instrumentation, List.of(resolvedPath));
        }
    }

    private static Path showFirstRunDialogAndAwaitResolution() {
        Path[] holder = new Path[1];
        try {
            SwingUtilities.invokeAndWait(() -> {
                KalkanFirstRunDialog dialog = new KalkanFirstRunDialog();
                dialog.setVisible(true);
                holder[0] = dialog.resolvedPath();
            });
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        } catch (InvocationTargetException e) {
            throw new IllegalStateException(e.getCause());
        }
        return holder[0];
    }

    private static void showAboutDialog() {
        SwingUtilities.invokeLater(() -> {
            Window owner = KeyboardFocusManager.getCurrentKeyboardFocusManager().getActiveWindow();
            JOptionPane.showMessageDialog(
                owner,
                GuiMessages.get(GuiMsgKey.ABOUT_MESSAGE, GuiVersion.VALUE),
                GuiMessages.get(GuiMsgKey.WINDOW_TITLE),
                JOptionPane.INFORMATION_MESSAGE);
        });
    }
}
