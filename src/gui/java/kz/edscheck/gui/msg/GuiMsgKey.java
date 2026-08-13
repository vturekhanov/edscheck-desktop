package kz.edscheck.gui.msg;

public enum GuiMsgKey {

    WINDOW_TITLE("window.title", 0),

    BUTTON_CHOOSE_FILE("button.choose_file", 0),
    FILE_CHOOSER_TITLE("file_chooser.title", 0),
    STATUS_IDLE("status.idle", 0),
    STATUS_BUSY("status.busy", 0),

    EMPTY_STATE_HINT("empty_state.hint", 0),
    ERROR_TIMEOUT("error.timeout", 0),
    ERROR_GENERIC("error.generic", 1),
    LABEL_FILE("label.file", 0),
    LABEL_SIGNATURES_TOTAL("label.signatures_total", 0),
    LABEL_DOCUMENT("label.document", 0),

    STATUS_AWAITING_DOCUMENT("status.awaiting_document", 0),
    BUTTON_CHOOSE_DOCUMENT("button.choose_document", 0),
    DOCUMENT_CHOOSER_TITLE("document_chooser.title", 0),
    BUTTON_CANCEL_DOCUMENT("button.cancel_document", 0),

    ERROR_CONTAINER("error.container", 1),
    ERROR_LIBRARY("error.library", 1),
    ERROR_UNEXPECTED("error.unexpected", 1),

    ERROR_LIBRARY_STARTUP("error.library_startup", 0),

    BUTTON_EXPAND("button.expand", 0),
    BUTTON_COLLAPSE("button.collapse", 0),

    BUTTON_EXTRACT_DOCUMENT("button.extract_document", 0),
    EXTRACT_CHOOSER_TITLE("extract_chooser.title", 0),
    EXTRACT_SUCCESS("extract.success", 1),

    GLYPH_GENUINE("glyph.genuine", 0),
    GLYPH_GENUINE_WARNINGS("glyph.genuine_warnings", 0),
    GLYPH_INVALID("glyph.invalid", 0),

    FOOTER_DISCLAIMER("footer.disclaimer", 1),
    FOOTER_DISCLAIMER_LINK_TEXT("footer.disclaimer_link_text", 0),

    ABOUT_MESSAGE("about.message", 2),

    BUTTON_ABOUT("button.about", 0),

    KALKAN_FIRST_RUN_TITLE("kalkan_first_run.title", 0),
    KALKAN_FIRST_RUN_EXPLANATION("kalkan_first_run.explanation", 1),
    KALKAN_FIRST_RUN_DROP_HINT("kalkan_first_run.drop_hint", 1),
    KALKAN_FIRST_RUN_FILE_CHOOSER_TITLE("kalkan_first_run.file_chooser_title", 0),
    KALKAN_FIRST_RUN_ERROR_MISMATCH("kalkan_first_run.error_mismatch", 0),
    KALKAN_FIRST_RUN_ERROR_UNEXPECTED("kalkan_first_run.error_unexpected", 1),

    KALKAN_AGENT_UNAVAILABLE("kalkan_first_run.agent_unavailable", 0),

    MESSAGES_ARG_COUNT_MISMATCH("messages.arg_count_mismatch", 3);

    private final String key;
    private final int argCount;

    GuiMsgKey(String key, int argCount) {
        this.key = key;
        this.argCount = argCount;
    }

    public String key() {
        return key;
    }

    public int argCount() {
        return argCount;
    }
}
