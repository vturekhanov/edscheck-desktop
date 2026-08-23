package kz.edscheck.gui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.awt.Rectangle;
import java.awt.Window;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionAdapter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JViewport;
import javax.swing.Scrollable;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.TransferHandler;
import javax.swing.UIManager;

import com.formdev.flatlaf.icons.FlatOptionPaneInformationIcon;
import com.formdev.flatlaf.util.SystemFileChooser;
import com.formdev.flatlaf.util.SystemInfo;

import kz.edscheck.app.RunnerParams;
import kz.edscheck.ddcard.Ddcard;
import kz.edscheck.ddcard.DdcardContent;
import kz.edscheck.domain.Certificate;
import kz.edscheck.domain.CheckStatus;
import kz.edscheck.domain.DocumentSource;
import kz.edscheck.domain.Environment;
import kz.edscheck.domain.Stage;
import kz.edscheck.domain.Verdict;
import kz.edscheck.errors.ContainerException;
import kz.edscheck.errors.EdsCheckException;
import kz.edscheck.gui.msg.GuiMessages;
import kz.edscheck.gui.msg.GuiMsgKey;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.parsing.ContainerFormat;
import kz.edscheck.parsing.ContentExtraction;
import kz.edscheck.trace.Trace;
import kz.edscheck.trust.KalkanJarException;
import kz.edscheck.trust.LibraryJarException;
import kz.edscheck.trust.LibraryJars;
import kz.edscheck.xml.XmlContentExtraction;
import kz.edscheck.xml.XmlDetect;
import kz.edscheck.xml.XmlExtractionPlan;

public final class MainPanel extends JPanel {

    private static final Color COLOR_WARN = new Color(0xb2, 0x6a, 0x00);
    private static final Color COLOR_FAIL = new Color(0xc6, 0x28, 0x28);
    private static final Color COLOR_PASS = new Color(0x2e, 0x7d, 0x32);

    private static final float VERDICT_FONT_SIZE_DELTA = 2f;

    private static final float ABOUT_ICON_SCALE = 0.5625f;

    private static final String SPECIALIST_URL =
        "https://sigex.kz/blog/2021-01-25-digital-signatures-in-courts/#where-to-find-experts";

    private static final DateTimeFormatter DT_FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss xxx", Locale.ROOT);

    private static final String EMOJI_FONT_FAMILY = resolveEmojiFontFamily();

    private static String resolveEmojiFontFamily() {
        Set<String> available = Set.of(
            GraphicsEnvironment.getLocalGraphicsEnvironment().getAvailableFontFamilyNames(Locale.ROOT));
        for (String family : new String[] {"Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji"}) {
            if (available.contains(family)) {
                return family;
            }
        }
        return null;
    }

    static boolean colorEmojiSupported() {
        return SystemInfo.isMacOS;
    }

    private static boolean systemAboutMenuAvailable() {
        return Desktop.isDesktopSupported()
            && Desktop.getDesktop().isSupported(Desktop.Action.APP_ABOUT);
    }

    private static JButton buildAboutButton() {
        JButton button = new JButton(aboutIcon());
        button.setToolTipText(GuiMessages.get(GuiMsgKey.BUTTON_ABOUT));
        button.putClientProperty("JButton.buttonType", "borderless");
        button.addActionListener(e -> AboutDialog.show());
        return button;
    }

    private static Icon aboutIcon() {
        FlatOptionPaneInformationIcon icon = new FlatOptionPaneInformationIcon();
        icon.setScale(ABOUT_ICON_SCALE);
        return icon;
    }

    enum Kind { PASS, WARN, FAIL }

    private static String glyphFor(Kind kind) {
        return switch (kind) {
            case PASS -> GuiMessages.get(GuiMsgKey.GLYPH_GENUINE);
            case WARN -> GuiMessages.get(GuiMsgKey.GLYPH_GENUINE_WARNINGS);
            case FAIL -> GuiMessages.get(GuiMsgKey.GLYPH_INVALID);
        };
    }

    private static Icon iconFor(Kind kind, int size) {
        return switch (kind) {
            case PASS -> new StatusIcons.Pass(size, COLOR_PASS);
            case WARN -> new StatusIcons.Warn(size, COLOR_WARN);
            case FAIL -> new StatusIcons.Fail(size, COLOR_FAIL);
        };
    }

    private static final long DETECT_PEEK_MAX_BYTES = 500L * 1024 * 1024;

    private static final Set<String> EXTRACTABLE_CONTAINER_FORMATS =
        Set.of("cms", "ddcard", "xades", "xmldsig", "xmlesf");

    private static final Set<String> SHOWABLE_CONTAINER_FORMATS = Set.of("xades", "xmldsig", "xmlesf");

    private static final int SIGNED_CONTENT_MAX_CHARACTERS = 100_000;

    private final CheckService checkService;
    final JButton chooseButton;
    final JLabel statusLabel;
    final JProgressBar busyIndicator;
    final JButton chooseDocumentButton;
    final JButton cancelDocumentButton;
    final ResultsContainer resultsContainer;
    final JLabel footerPane;

    final JButton aboutButton;
    private volatile boolean busy;
    private ResultViewModel currentModel;
    private boolean detailed;

    private File pendingContainer;
    final JPanel documentRow;

    private File lastContainerFile;

    private boolean showingEmptyStateHint;

    public MainPanel(CheckService checkService) {
        super(new BorderLayout(8, 8));
        this.checkService = checkService;

        chooseButton = new JButton(GuiMessages.get(GuiMsgKey.BUTTON_CHOOSE_FILE));
        chooseButton.addActionListener(e -> onChooseFile());

        statusLabel = new JLabel(GuiMessages.get(GuiMsgKey.STATUS_IDLE));

        busyIndicator = new JProgressBar();
        busyIndicator.setIndeterminate(true);
        busyIndicator.setVisible(false);

        JPanel topLeft = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 8));
        topLeft.add(chooseButton);
        topLeft.add(statusLabel);
        topLeft.add(busyIndicator);

        JPanel top = new JPanel(new BorderLayout());
        top.add(topLeft, BorderLayout.WEST);
        aboutButton = systemAboutMenuAvailable() ? null : buildAboutButton();
        if (aboutButton != null) {
            JPanel topRight = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
            topRight.add(aboutButton);
            top.add(topRight, BorderLayout.EAST);
        }

        chooseDocumentButton = new JButton(GuiMessages.get(GuiMsgKey.BUTTON_CHOOSE_DOCUMENT));
        chooseDocumentButton.addActionListener(e -> onChooseDocument());
        cancelDocumentButton = new JButton(GuiMessages.get(GuiMsgKey.BUTTON_CANCEL_DOCUMENT));
        cancelDocumentButton.addActionListener(e -> onCancelDocument());

        documentRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        documentRow.add(chooseDocumentButton);
        documentRow.add(cancelDocumentButton);
        documentRow.setVisible(false);

        JPanel north = new JPanel();
        north.setLayout(new BoxLayout(north, BoxLayout.Y_AXIS));
        north.add(top);
        north.add(documentRow);

        resultsContainer = new ResultsContainer();

        resultsContainer.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        resultsContainer.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (showingEmptyStateHint) {
                    emptyStateClicked();
                }
            }
        });

        footerPane = buildFooter();

        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        add(north, BorderLayout.NORTH);
        add(new JScrollPane(resultsContainer), BorderLayout.CENTER);
        add(footerPane, BorderLayout.SOUTH);

        setTransferHandler(new FileDropHandler());
        showEmptyStateHint();
    }

    private JLabel buildFooter() {
        JLabel label = new JLabel(footerText());

        label.setBorder(BorderFactory.createEmptyBorder(8, 4, 8, 4));
        label.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                String href = HtmlLinkSupport.linkAt(label, e.getPoint());
                if (href != null) {
                    HtmlLinkSupport.openLink(href);
                }
            }
        });
        label.addMouseMotionListener(new MouseMotionAdapter() {
            @Override
            public void mouseMoved(MouseEvent e) {
                boolean overLink = HtmlLinkSupport.linkAt(label, e.getPoint()) != null;
                label.setCursor(Cursor.getPredefinedCursor(overLink ? Cursor.HAND_CURSOR : Cursor.DEFAULT_CURSOR));
            }
        });
        return label;
    }

    private static String footerText() {
        Color linkColor = UIManager.getColor("Label.foreground");
        String link = "<a href=\"" + SPECIALIST_URL + "\" style=\"color: rgb("
            + linkColor.getRed() + "," + linkColor.getGreen() + "," + linkColor.getBlue() + ");\">"
            + GuiMessages.get(GuiMsgKey.FOOTER_DISCLAIMER_LINK_TEXT) + "</a>";
        return "<html>" + GuiMessages.get(GuiMsgKey.FOOTER_DISCLAIMER, link) + "</html>";
    }

    @Override
    public void updateUI() {
        super.updateUI();
        if (footerPane != null) {
            footerPane.setText(footerText());
        }

        if (aboutButton != null && aboutButton.getIcon() != null) {
            aboutButton.setIcon(aboutIcon());
        }

        if (showingEmptyStateHint) {
            showEmptyStateHint();
        }
    }

    private void onChooseFile() {

        SystemFileChooser chooser = new SystemFileChooser();
        chooser.setDialogTitle(GuiMessages.get(GuiMsgKey.FILE_CHOOSER_TITLE));
        if (chooser.showOpenDialog(this) == SystemFileChooser.APPROVE_OPTION) {
            handleSelectedContainer(chooser.getSelectedFile());
        }
    }

    void handleSelectedContainer(File file) {

        clearResults();
        showEmptyStateHint();
        if (isDetachedContainer(peekBytes(file))) {
            pendingContainer = file;
            documentRow.setVisible(true);
            statusLabel.setText(GuiMessages.get(GuiMsgKey.STATUS_AWAITING_DOCUMENT));
        } else {
            pendingContainer = null;
            documentRow.setVisible(false);
            runCheck(file);
        }
    }

    private void onChooseDocument() {
        if (pendingContainer == null) {
            return;
        }
        SystemFileChooser chooser = new SystemFileChooser();
        chooser.setDialogTitle(GuiMessages.get(GuiMsgKey.DOCUMENT_CHOOSER_TITLE));
        if (chooser.showOpenDialog(this) == SystemFileChooser.APPROVE_OPTION) {
            chooseDocument(chooser.getSelectedFile());
        }
    }

    void chooseDocument(File document) {
        if (pendingContainer == null) {
            return;
        }
        File container = pendingContainer;
        pendingContainer = null;
        documentRow.setVisible(false);
        runCheck(container, document);
    }

    private void onCancelDocument() {
        pendingContainer = null;
        documentRow.setVisible(false);
        statusLabel.setText(GuiMessages.get(GuiMsgKey.STATUS_IDLE));
    }

    private static boolean isDetachedContainer(byte[] bytes) {
        return isDetachedCades(bytes) || isDetachedXml(bytes);
    }

    private static boolean isDetachedCades(byte[] bytes) {
        return bytes.length > 0 && bytes[0] == 0x30
            && ContainerFormat.looksLikeCades(bytes) && !ContainerFormat.isAttached(bytes);
    }

    private static boolean isDetachedXml(byte[] bytes) {
        return XmlDetect.looksLikeXml(bytes) && XmlDetect.looksLikeDetached(bytes);
    }

    private static byte[] peekBytes(File file) {
        long size = file.length();
        if (size <= 0 || size > DETECT_PEEK_MAX_BYTES) {
            return new byte[0];
        }
        try {
            return Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            return new byte[0];
        }
    }

    void runCheck(File file) {
        runCheck(file, null);
    }

    private void runCheck(File file, File document) {
        showBusy();
        lastContainerFile = file;
        DocumentSource documentSource = document != null ? DocumentSource.ofFile(document.toPath()) : null;
        String documentName = document != null ? document.getName() : null;
        RunnerParams params = new RunnerParams(
            DocumentSource.ofFile(file.toPath()), documentSource, documentName, file.getName(),
            "auto", "kalkan-java", Environment.PROD, List.of(), List.of(),
            false, null, Trace.NONE);
        checkService.submit(params, result -> SwingUtilities.invokeLater(() -> handleResult(result)));
    }

    private void handleResult(CheckService.Result result) {
        if (result instanceof CheckService.Result.Success success) {
            showResult(ResultViewModel.from(success.result()));
        } else if (result instanceof CheckService.Result.Timeout) {
            showError(GuiMessages.get(GuiMsgKey.ERROR_TIMEOUT));
        } else if (result instanceof CheckService.Result.Failure failure) {
            showError(errorMessage(failure.cause()));
        }
    }

    private static String errorMessage(Throwable cause) {
        String detail = cause.getMessage() != null ? cause.getMessage() : String.valueOf(cause);
        if (cause instanceof KalkanJarException || cause instanceof LibraryJarException) {
            return GuiMessages.get(GuiMsgKey.ERROR_LIBRARY, detail);
        }
        if (cause instanceof ContainerException) {
            return GuiMessages.get(GuiMsgKey.ERROR_CONTAINER, detail);
        }
        if (cause instanceof EdsCheckException) {
            return GuiMessages.get(GuiMsgKey.ERROR_GENERIC, detail);
        }
        return GuiMessages.get(GuiMsgKey.ERROR_UNEXPECTED, detail);
    }

    private void onExtractDocument(String containerFormat) {
        File container = lastContainerFile;
        if (container == null) {
            return;
        }
        String defaultName;

        DocumentSource materialized = null;
        try {
            if ("ddcard".equals(containerFormat)) {
                LibraryJars.verifyRuntime(LibraryJars.resolveDirFromSystemProperty());
                byte[] raw = Files.readAllBytes(container.toPath());
                DdcardContent ddcardContent = Ddcard.parseDdcard(raw);
                defaultName = ContentExtraction.sanitizeBasename(ddcardContent.documentName());
                materialized = ddcardContent.document();
            } else if (SHOWABLE_CONTAINER_FORMATS.contains(containerFormat)) {
                byte[] raw = Files.readAllBytes(container.toPath());
                XmlExtractionPlan plan = XmlContentExtraction.plan(raw, container.getName());
                defaultName = plan.defaultFileName();
                materialized = DocumentSource.ofBytes(plan.document());
            } else {
                String byExtension = ContentExtraction.defaultAttachedName(container.toPath());
                defaultName = byExtension != null ? byExtension : container.getName();
            }
        } catch (Exception e) {
            showExtractError(e);
            return;
        }

        SystemFileChooser chooser = new SystemFileChooser();
        chooser.setDialogTitle(GuiMessages.get(GuiMsgKey.EXTRACT_CHOOSER_TITLE));
        chooser.setCurrentDirectory(container.getAbsoluteFile().getParentFile());
        chooser.setSelectedFile(new File(defaultName));
        if (chooser.showSaveDialog(this) != SystemFileChooser.APPROVE_OPTION) {
            return;
        }
        Path target = chooser.getSelectedFile().toPath();

        chooseButton.setEnabled(false);
        DocumentSource finalMaterialized = materialized;
        new Thread(() -> {
            Throwable error = null;
            try {
                if (finalMaterialized != null) {
                    ContentExtraction.copyAtomically(finalMaterialized, target);
                } else {
                    ContentExtraction.extract(DocumentSource.ofFile(container.toPath()), target);
                }
            } catch (Throwable t) {
                error = t;
            }
            Throwable finalError = error;
            SwingUtilities.invokeLater(() -> {
                chooseButton.setEnabled(!busy);
                if (finalError != null) {
                    showExtractError(finalError);
                } else {
                    JOptionPane.showMessageDialog(this, GuiMessages.get(GuiMsgKey.EXTRACT_SUCCESS, target.getFileName()),
                        GuiMessages.get(GuiMsgKey.WINDOW_TITLE), JOptionPane.INFORMATION_MESSAGE);
                }
            });
        }, "gui-extract").start();
    }

    private void onShowSignedContent(String containerFormat) {
        File container = lastContainerFile;
        if (container == null) {
            return;
        }
        XmlExtractionPlan plan;
        try {
            byte[] raw = Files.readAllBytes(container.toPath());
            plan = XmlContentExtraction.plan(raw, container.getName());
        } catch (Exception e) {
            showExtractError(e);
            return;
        }
        String full = new String(plan.document(), StandardCharsets.UTF_8);
        boolean truncated = full.length() > SIGNED_CONTENT_MAX_CHARACTERS;
        String text = truncated ? full.substring(0, SIGNED_CONTENT_MAX_CHARACTERS) : full;
        showSignedContentDialog(text, truncated, containerFormat);
    }

    private void showSignedContentDialog(String text, boolean truncated, String containerFormat) {
        Window owner = SwingUtilities.getWindowAncestor(this);
        JDialog dialog = new JDialog(owner, GuiMessages.get(GuiMsgKey.WINDOW_TITLE), Dialog.ModalityType.APPLICATION_MODAL);

        JLabel title = new JLabel(GuiMessages.get(GuiMsgKey.SIGNED_CONTENT_TITLE));
        title.setFont(title.getFont().deriveFont(Font.BOLD));
        title.setBorder(BorderFactory.createEmptyBorder(12, 12, 8, 12));

        JTextArea textArea = new JTextArea(text);
        textArea.setEditable(false);
        textArea.setLineWrap(true);
        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, textArea.getFont().getSize()));
        textArea.setCaretPosition(0);
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setBorder(BorderFactory.createEmptyBorder(0, 12, 0, 12));

        JPanel bottom = new VerticalPanel();
        bottom.setBorder(BorderFactory.createEmptyBorder(8, 12, 12, 12));
        if (truncated) {
            JLabel truncatedLabel = new JLabel(
                GuiMessages.get(GuiMsgKey.SIGNED_CONTENT_TRUNCATED, SIGNED_CONTENT_MAX_CHARACTERS));
            truncatedLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
            truncatedLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
            bottom.add(truncatedLabel);
        }
        JPanel buttonsRow = new JPanel(new BorderLayout());
        buttonsRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        JButton closeButton = new JButton(GuiMessages.get(GuiMsgKey.BUTTON_CLOSE));
        closeButton.addActionListener(e -> dialog.dispose());
        JButton extractButton = new JButton(GuiMessages.get(GuiMsgKey.BUTTON_EXTRACT_DOCUMENT));
        extractButton.addActionListener(e -> {
            dialog.dispose();
            onExtractDocument(containerFormat);
        });
        buttonsRow.add(closeButton, BorderLayout.WEST);
        buttonsRow.add(extractButton, BorderLayout.EAST);
        bottom.add(buttonsRow);

        JPanel content = new JPanel(new BorderLayout());
        content.add(title, BorderLayout.NORTH);
        content.add(scrollPane, BorderLayout.CENTER);
        content.add(bottom, BorderLayout.SOUTH);

        dialog.getRootPane().setDefaultButton(closeButton);
        dialog.setContentPane(content);
        dialog.setSize(600, 450);
        dialog.setLocationRelativeTo(owner);
        dialog.setVisible(true);
    }

    private void showExtractError(Throwable cause) {
        JOptionPane.showMessageDialog(this, errorMessage(cause),
            GuiMessages.get(GuiMsgKey.WINDOW_TITLE), JOptionPane.ERROR_MESSAGE);
    }

    void showBusy() {
        busy = true;
        chooseButton.setEnabled(false);
        statusLabel.setText(GuiMessages.get(GuiMsgKey.STATUS_BUSY));
        busyIndicator.setVisible(true);
    }

    private void showIdle() {
        busy = false;
        chooseButton.setEnabled(true);
        statusLabel.setText(GuiMessages.get(GuiMsgKey.STATUS_IDLE));
        busyIndicator.setVisible(false);
    }

    private void clearResults() {
        currentModel = null;
        resultsContainer.removeAll();
        resultsContainer.revalidate();
        resultsContainer.repaint();
    }

    private void showEmptyStateHint() {
        resultsContainer.removeAll();
        JLabel hint = new JLabel("<html><div style=\"text-align:center\">"
            + GuiMessages.get(GuiMsgKey.EMPTY_STATE_HINT) + "</div></html>");
        hint.setHorizontalAlignment(SwingConstants.CENTER);
        hint.setAlignmentX(Component.CENTER_ALIGNMENT);
        hint.setForeground(UIManager.getColor("Label.disabledForeground"));

        MouseAdapter opener = new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                emptyStateClicked();
            }
        };
        Component glueTop = Box.createVerticalGlue();
        Component glueBottom = Box.createVerticalGlue();
        for (Component c : List.of(hint, glueTop, glueBottom)) {
            c.addMouseListener(opener);
        }

        resultsContainer.add(glueTop);
        resultsContainer.add(hint);
        resultsContainer.add(glueBottom);
        resultsContainer.revalidate();
        resultsContainer.repaint();
        showingEmptyStateHint = true;
    }

    private void emptyStateClicked() {
        emptyStateTarget().doClick();
    }

    JButton emptyStateTarget() {
        return pendingContainer != null ? chooseDocumentButton : chooseButton;
    }

    void showError(String message) {
        showIdle();
        clearResults();
        showingEmptyStateHint = false;
        Font font = new JLabel().getFont();
        resultsContainer.add(iconRow(Kind.FAIL, message, COLOR_FAIL, font));
        resultsContainer.revalidate();
        resultsContainer.repaint();
    }

    void showResult(ResultViewModel model) {
        showIdle();
        currentModel = model;
        detailed = false;
        renderResult();
    }

    void toggleDetailed() {
        detailed = !detailed;
        renderResult();
    }

    private void renderResult() {
        showingEmptyStateHint = false;
        resultsContainer.removeAll();
        resultsContainer.add(headerPanel(currentModel));
        for (ResultViewModel.SignatureView sig : currentModel.signatures()) {
            resultsContainer.add(detailed ? signaturePanel(sig, currentModel.mixedAuthority()) : summaryRow(sig));
        }
        resultsContainer.revalidate();
        resultsContainer.repaint();
    }

    private VerticalPanel headerPanel(ResultViewModel model) {
        VerticalPanel panel = new VerticalPanel();
        panel.add(row(GuiMessages.get(GuiMsgKey.LABEL_FILE), model.filePath()));
        panel.add(row(Messages.get(MsgKey.LABEL_CA), model.caLabel()));
        panel.add(row(GuiMessages.get(GuiMsgKey.LABEL_SIGNATURES_TOTAL), String.valueOf(model.signaturesTotal())));
        if (model.documentName() != null) {
            panel.add(row(GuiMessages.get(GuiMsgKey.LABEL_DOCUMENT), model.documentName()));
        }
        JButton toggle = new JButton(GuiMessages.get(
            detailed ? GuiMsgKey.BUTTON_COLLAPSE : GuiMsgKey.BUTTON_EXPAND));
        toggle.addActionListener(e -> toggleDetailed());

        JPanel actionsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        actionsRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        actionsRow.add(toggle);
        if (EXTRACTABLE_CONTAINER_FORMATS.contains(model.containerFormat())) {
            boolean showable = SHOWABLE_CONTAINER_FORMATS.contains(model.containerFormat());
            JButton actionButton = new JButton(GuiMessages.get(
                showable ? GuiMsgKey.BUTTON_SHOW_DOCUMENT : GuiMsgKey.BUTTON_EXTRACT_DOCUMENT));
            actionButton.addActionListener(e -> {
                if (showable) {
                    onShowSignedContent(model.containerFormat());
                } else {
                    onExtractDocument(model.containerFormat());
                }
            });
            actionsRow.add(actionButton);
        }

        actionsRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, actionsRow.getPreferredSize().height));
        panel.add(actionsRow);

        panel.add(Box.createVerticalStrut(8));
        return panel;
    }

    private JComponent summaryRow(ResultViewModel.SignatureView sig) {
        Font base = new JLabel().getFont();
        Font font = base.deriveFont(Font.BOLD, base.getSize2D() + VERDICT_FONT_SIZE_DELTA);
        String text = sig.verdictLabel() + " — " + sig.signerDisplayName();
        return iconRow(verdictIcon(sig), text, verdictColor(sig), font);
    }

    private VerticalPanel signaturePanel(ResultViewModel.SignatureView sig, boolean mixed) {
        VerticalPanel panel = new VerticalPanel();
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, Color.LIGHT_GRAY),
            BorderFactory.createEmptyBorder(8, 0, 0, 0)));

        Font base = new JLabel().getFont();
        Font font = base.deriveFont(Font.BOLD, base.getSize2D() + VERDICT_FONT_SIZE_DELTA);
        String text = (sig.index() + 1) + "/" + sig.total() + " — " + sig.verdictLabel();
        panel.add(iconRow(verdictIcon(sig), text, verdictColor(sig), font));

        if (mixed) {
            panel.add(row(Messages.get(MsgKey.LABEL_CA), sig.caLabel()));
        }
        panel.add(row(Messages.get(MsgKey.LABEL_SIGNER), sig.signerDisplayName()));
        Certificate signer = sig.signer();
        if (nonEmpty(signer.iin())) {
            panel.add(row(Messages.get(MsgKey.LABEL_IIN), signer.iin()));
        }
        if (nonEmpty(signer.bin())) {
            panel.add(row(Messages.get(MsgKey.LABEL_BIN), signer.bin()));
        }
        if (!signer.subjectRoles().isEmpty()) {
            panel.add(row(Messages.get(MsgKey.LABEL_ROLE), String.join(" / ", signer.subjectRoles())));
        }
        if (nonEmpty(signer.organization())) {
            panel.add(row(Messages.get(MsgKey.LABEL_ORGANIZATION), signer.organization()));
        }
        String validity = certValidityText(signer.notBefore(), signer.notAfter());
        if (!validity.isEmpty()) {
            panel.add(row(Messages.get(MsgKey.LABEL_CERTIFICATE), validity));
        }
        panel.add(row(Messages.get(MsgKey.LABEL_REFERENCE_TIME),
            fmtDt(sig.referenceTime().value()) + " (" + sig.referenceTimeSourceLabel() + ")"));

        JLabel checksLabel = new JLabel(Messages.get(MsgKey.LABEL_CHECKS) + ":");
        checksLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        checksLabel.setFont(checksLabel.getFont().deriveFont(Font.BOLD));
        panel.add(checksLabel);

        for (ResultViewModel.CheckView check : sig.checks()) {
            if (check.check().status() != CheckStatus.SKIP) {
                panel.add(checkRow(check));
            }
        }
        return panel;
    }

    private JComponent checkRow(ResultViewModel.CheckView check) {
        StringBuilder text = new StringBuilder(check.stageLabel());
        String detail = check.check().detail();
        if (check.check().stage() == Stage.REVOCATION) {

            String source = check.sourceLabel() != null
                ? check.sourceLabel()
                : Messages.get(MsgKey.CHECK_REVOCATION_NOT_VERIFIED);
            text.append(' ').append(source);
            if (check.check().status() != CheckStatus.PASS && detail != null) {
                text.append(" — ").append(detail);
            }
        } else if (detail != null) {
            text.append(" — ").append(detail);
        }
        if (check.check().online()) {
            text.append(' ').append(Messages.get(MsgKey.CHECK_ONLINE_MARK));
        }
        JComponent row = iconRow(statusIcon(check.check().status()), text.toString(),
            statusColor(check.check().status()), new JLabel().getFont());
        row.setBorder(BorderFactory.createEmptyBorder(0, 12, 0, 0));
        return row;
    }

    private static JComponent iconRow(Kind kind, String text, Color color, Font textFont) {
        int iconSize = Math.round(textFont.getSize2D());
        JLabel iconLabel;
        if (colorEmojiSupported() && EMOJI_FONT_FAMILY != null) {
            iconLabel = new JLabel(glyphFor(kind));
            iconLabel.setFont(new Font(EMOJI_FONT_FAMILY, Font.PLAIN, iconSize));
        } else {
            iconLabel = new JLabel(iconFor(kind, iconSize));
        }
        JLabel textLabel = new JLabel("<html>" + escapeHtml(text) + "</html>");
        textLabel.setFont(textFont);
        if (color != null) {
            textLabel.setForeground(color);
        }

        iconLabel.setAlignmentY(Component.TOP_ALIGNMENT);
        textLabel.setAlignmentY(Component.TOP_ALIGNMENT);

        Box box = new Box(BoxLayout.X_AXIS) {

            @Override
            public Dimension getMaximumSize() {
                return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
            }
        };
        box.setAlignmentX(Component.LEFT_ALIGNMENT);
        box.add(iconLabel);
        box.add(Box.createHorizontalStrut(6));
        box.add(textLabel);
        return box;
    }

    private static JLabel row(String label, String value) {
        JLabel out = new JLabel("<html><b>" + escapeHtml(label) + ":</b> " + escapeHtml(value) + "</html>");
        out.setAlignmentX(Component.LEFT_ALIGNMENT);
        return out;
    }

    private static String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static boolean nonEmpty(String s) {
        return s != null && !s.isEmpty();
    }

    private static String fmtDt(Instant value) {
        return value.atZone(ZoneId.systemDefault()).format(DT_FMT);
    }

    private static String certValidityText(Instant notBefore, Instant notAfter) {
        if (notBefore != null && notAfter != null) {
            return GuiMessages.get(GuiMsgKey.CERT_VALID_FROM_TO, fmtDt(notBefore), fmtDt(notAfter));
        }
        if (notAfter != null) {
            return GuiMessages.get(GuiMsgKey.CERT_VALID_TO, fmtDt(notAfter));
        }
        if (notBefore != null) {
            return GuiMessages.get(GuiMsgKey.CERT_VALID_FROM, fmtDt(notBefore));
        }
        return "";
    }

    static Kind verdictIcon(ResultViewModel.SignatureView sig) {
        if (sig.verdict() != Verdict.GENUINE) {
            return Kind.FAIL;
        }
        return sig.warnings().isEmpty() ? Kind.PASS : Kind.WARN;
    }

    private static Color verdictColor(ResultViewModel.SignatureView sig) {
        if (sig.verdict() != Verdict.GENUINE) {
            return COLOR_FAIL;
        }
        return sig.warnings().isEmpty() ? null : COLOR_WARN;
    }

    private static Color statusColor(CheckStatus status) {
        return switch (status) {
            case PASS -> null;
            case WARN -> COLOR_WARN;
            case FAIL, NOT_VERIFIED -> COLOR_FAIL;
            case SKIP -> null;
        };
    }

    static Kind statusIcon(CheckStatus status) {
        return switch (status) {
            case PASS -> Kind.PASS;
            case WARN -> Kind.WARN;
            case FAIL, NOT_VERIFIED -> Kind.FAIL;
            case SKIP -> null;
        };
    }

    private static final class VerticalPanel extends JPanel {
        VerticalPanel() {
            setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
            setAlignmentX(Component.LEFT_ALIGNMENT);
        }
    }

    static final class ResultsContainer extends JPanel implements Scrollable {
        ResultsContainer() {
            setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        }

        @Override
        public Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
            return 16;
        }

        @Override
        public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
            return orientation == SwingConstants.VERTICAL ? visibleRect.height : visibleRect.width;
        }

        @Override
        public boolean getScrollableTracksViewportWidth() {
            return true;
        }

        @Override
        public boolean getScrollableTracksViewportHeight() {
            Container parent = getParent();
            if (!(parent instanceof JViewport viewport)) {
                return false;
            }
            return viewport.getHeight() > getPreferredSize().height;
        }
    }

    private final class FileDropHandler extends TransferHandler {
        @Override
        public boolean canImport(TransferSupport support) {
            return !busy && support.isDataFlavorSupported(DataFlavor.javaFileListFlavor);
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
                if (pendingContainer != null) {
                    chooseDocument(files.get(0));
                } else {
                    handleSelectedContainer(files.get(0));
                }
                return true;
            } catch (UnsupportedFlavorException | IOException e) {
                return false;
            }
        }
    }
}
