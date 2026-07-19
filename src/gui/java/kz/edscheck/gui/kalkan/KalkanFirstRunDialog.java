package kz.edscheck.gui.kalkan;

import java.awt.Dimension;
import java.awt.Frame;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.nio.file.Path;

import javax.swing.JDialog;
import javax.swing.WindowConstants;

import kz.edscheck.gui.msg.GuiMessages;
import kz.edscheck.gui.msg.GuiMsgKey;

public final class KalkanFirstRunDialog extends JDialog {
    private Path resolvedPath;

    public KalkanFirstRunDialog() {
        super((Frame) null, GuiMessages.get(GuiMsgKey.KALKAN_FIRST_RUN_TITLE), true);
        setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                System.exit(0);
            }
        });
        setContentPane(new KalkanFirstRunPanel(KalkanResolver.storagePath(), path -> {
            resolvedPath = path;
            setVisible(false);
            dispose();
        }));

        setSize(480, 420);
        setMinimumSize(new Dimension(360, 280));
        setResizable(true);
        setLocationRelativeTo(null);
    }

    public Path resolvedPath() {
        return resolvedPath;
    }
}
