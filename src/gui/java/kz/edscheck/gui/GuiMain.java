package kz.edscheck.gui;

import java.awt.Desktop;
import java.awt.Taskbar;

import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

import com.formdev.flatlaf.FlatLaf;

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

        
        
        
        
        
        ThemeWatcher themeWatcher = new ThemeWatcher(OsThemeDetector::detect, changed ->
            SwingUtilities.invokeLater(() -> {
                ThemeApplier.apply(changed);
                FlatLaf.updateUI();
            }), theme);
        themeWatcher.start();

        
        
        
        
        
        
        if (Taskbar.isTaskbarSupported()) {
            Taskbar taskbar = Taskbar.getTaskbar();
            if (taskbar.isSupported(Taskbar.Feature.ICON_IMAGE)) {
                taskbar.setIconImage(AppIcon.image());
            }
        }

        
        
        
        
        
        
        
        
        
        
        if (Desktop.isDesktopSupported()) {
            Desktop desktop = Desktop.getDesktop();
            if (desktop.isSupported(Desktop.Action.APP_ABOUT)) {
                desktop.setAboutHandler(e -> showAboutDialog());
            }
        }

        SwingUtilities.invokeLater(() -> new MainWindow().setVisible(true));
    }

    private static void showAboutDialog() {
        SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(
            null,
            GuiMessages.get(GuiMsgKey.ABOUT_MESSAGE, GuiVersion.VALUE),
            GuiMessages.get(GuiMsgKey.WINDOW_TITLE),
            JOptionPane.INFORMATION_MESSAGE));
    }
}
