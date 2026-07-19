package kz.edscheck.gui;

import java.awt.Desktop;
import java.awt.Point;
import java.awt.Rectangle;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.swing.JLabel;
import javax.swing.plaf.basic.BasicHTML;
import javax.swing.text.AttributeSet;
import javax.swing.text.Position;
import javax.swing.text.View;
import javax.swing.text.html.HTML;
import javax.swing.text.html.HTMLDocument;

public final class HtmlLinkSupport {
    private HtmlLinkSupport() {
    }

    public static String linkAt(JLabel label, Point point) {
        if (!(label.getClientProperty(BasicHTML.propertyKey) instanceof View view)) {
            return null;
        }
        Position.Bias[] bias = new Position.Bias[1];
        int pos = view.viewToModel(point.x, point.y, new Rectangle(0, 0, label.getWidth(), label.getHeight()), bias);
        if (pos < 0 || !(view.getDocument() instanceof HTMLDocument doc)) {
            return null;
        }
        AttributeSet charAttrs = doc.getCharacterElement(pos).getAttributes();
        if (charAttrs.getAttribute(HTML.Tag.A) instanceof AttributeSet anchorAttrs) {
            return (String) anchorAttrs.getAttribute(HTML.Attribute.HREF);
        }
        return null;
    }

    public static void openLink(String href) {
        if (!Desktop.isDesktopSupported()) {
            return;
        }
        Desktop desktop = Desktop.getDesktop();
        if (!desktop.isSupported(Desktop.Action.BROWSE)) {
            return;
        }
        try {
            desktop.browse(new URI(href));
        } catch (IOException | URISyntaxException e) {

        }
    }
}
