package kz.edscheck.gui;

import java.awt.KeyboardFocusManager;
import java.awt.Window;

import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

import kz.edscheck.Version;
import kz.edscheck.gui.msg.GuiMessages;
import kz.edscheck.gui.msg.GuiMsgKey;

final class AboutDialog {
    private AboutDialog() {
    }

    static void show() {
        SwingUtilities.invokeLater(() -> {
            Window owner = KeyboardFocusManager.getCurrentKeyboardFocusManager().getActiveWindow();
            JOptionPane.showMessageDialog(
                owner,
                GuiMessages.get(GuiMsgKey.ABOUT_MESSAGE, GuiVersion.VALUE, Version.VALUE),
                GuiMessages.get(GuiMsgKey.WINDOW_TITLE),
                JOptionPane.INFORMATION_MESSAGE);
        });
    }
}
