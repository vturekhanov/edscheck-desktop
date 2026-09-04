package kz.edscheck.gui;

import javax.swing.JFrame;
import javax.swing.WindowConstants;

import kz.edscheck.gui.msg.GuiMessages;
import kz.edscheck.gui.msg.GuiMsgKey;

public final class MainWindow extends JFrame {

    public MainWindow(boolean informationalMode) {
        super(GuiMessages.get(GuiMsgKey.WINDOW_TITLE));
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setIconImage(AppIcon.image());
        setContentPane(new MainPanel(CheckService.forProduction(), informationalMode));
        setSize(900, 600);
        setLocationRelativeTo(null);
    }
}
