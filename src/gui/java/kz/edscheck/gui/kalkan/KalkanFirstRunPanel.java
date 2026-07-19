package kz.edscheck.gui.kalkan;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionAdapter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.function.Consumer;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import javax.swing.TransferHandler;

import com.formdev.flatlaf.util.SystemFileChooser;

import kz.edscheck.gui.HtmlLinkSupport;
import kz.edscheck.gui.msg.GuiMessages;
import kz.edscheck.gui.msg.GuiMsgKey;
import kz.edscheck.trust.KalkanJar;
import kz.edscheck.trust.KalkanJarException;

public final class KalkanFirstRunPanel extends JPanel {
    private static final Color COLOR_ERROR = new Color(0xc6, 0x28, 0x28);

    private static final String KALKAN_SDK_URL = "https://sdk.pki.gov.kz";

    private final Path destination;
    private final Consumer<Path> onResolved;

    final JLabel errorLabel;

    public KalkanFirstRunPanel(Path destination, Consumer<Path> onResolved) {
        this.destination = destination;
        this.onResolved = onResolved;

        String link = "<a href=\"" + KALKAN_SDK_URL + "\">" + KALKAN_SDK_URL + "</a>";
        JLabel explanation = new JLabel(htmlWrap(GuiMessages.get(GuiMsgKey.KALKAN_FIRST_RUN_EXPLANATION, link)));
        explanation.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                String href = HtmlLinkSupport.linkAt(explanation, e.getPoint());
                if (href != null) {
                    HtmlLinkSupport.openLink(href);
                }
            }
        });
        explanation.addMouseMotionListener(new MouseMotionAdapter() {
            @Override
            public void mouseMoved(MouseEvent e) {
                boolean overLink = HtmlLinkSupport.linkAt(explanation, e.getPoint()) != null;
                explanation.setCursor(Cursor.getPredefinedCursor(overLink ? Cursor.HAND_CURSOR : Cursor.DEFAULT_CURSOR));
            }
        });

        JLabel dropHint = new JLabel(
            htmlWrap("<center>" + GuiMessages.get(GuiMsgKey.KALKAN_FIRST_RUN_DROP_HINT, KalkanResolver.STORAGE_FILENAME) + "</center>"),
            SwingConstants.CENTER);
        JButton chooseButton = new JButton(GuiMessages.get(GuiMsgKey.BUTTON_CHOOSE_FILE));
        chooseButton.addActionListener(e -> onChooseFile());

        JPanel dropZone = new JPanel();
        dropZone.setLayout(new BoxLayout(dropZone, BoxLayout.Y_AXIS));
        dropZone.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color.GRAY, 1),
            BorderFactory.createEmptyBorder(24, 16, 24, 16)));
        dropHint.setAlignmentX(CENTER_ALIGNMENT);
        chooseButton.setAlignmentX(CENTER_ALIGNMENT);
        dropZone.add(dropHint);
        dropZone.add(javax.swing.Box.createVerticalStrut(12));
        dropZone.add(chooseButton);

        errorLabel = new JLabel(" ");
        errorLabel.setForeground(COLOR_ERROR);

        setLayout(new BorderLayout(0, 16));
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));
        add(explanation, BorderLayout.NORTH);
        add(dropZone, BorderLayout.CENTER);

        add(errorLabel, BorderLayout.SOUTH);

        setTransferHandler(new FileDropHandler());
    }

    private static String htmlWrap(String text) {
        return "<html>" + text + "</html>";
    }

    private void onChooseFile() {
        SystemFileChooser chooser = new SystemFileChooser();
        chooser.setDialogTitle(GuiMessages.get(GuiMsgKey.KALKAN_FIRST_RUN_FILE_CHOOSER_TITLE));
        if (chooser.showOpenDialog(this) == SystemFileChooser.APPROVE_OPTION) {
            handleSelectedFile(chooser.getSelectedFile());
        }
    }

    void handleSelectedFile(File file) {
        try {
            KalkanJar.verify(file.toPath());
        } catch (KalkanJarException e) {
            showError(GuiMessages.get(GuiMsgKey.KALKAN_FIRST_RUN_ERROR_MISMATCH));
            return;
        }
        try {
            Path parent = destination.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.copy(file.toPath(), destination, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            showError(GuiMessages.get(GuiMsgKey.KALKAN_FIRST_RUN_ERROR_UNEXPECTED, e.getMessage()));
            return;
        }
        clearError();
        onResolved.accept(destination);
    }

    private void showError(String message) {
        errorLabel.setText(htmlWrap(message));
    }

    private void clearError() {
        errorLabel.setText(" ");
    }

    private final class FileDropHandler extends TransferHandler {
        @Override
        public boolean canImport(TransferSupport support) {
            return support.isDataFlavorSupported(DataFlavor.javaFileListFlavor);
        }

        @Override
        public boolean importData(TransferSupport support) {
            if (!canImport(support)) {
                return false;
            }
            try {
                @SuppressWarnings("unchecked")
                List<File> files =
                    (List<File>) support.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);
                if (files.isEmpty()) {
                    return false;
                }
                handleSelectedFile(files.get(0));
                return true;
            } catch (UnsupportedFlavorException | IOException e) {
                return false;
            }
        }
    }
}
