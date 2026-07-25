package kz.edscheck.gui;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Component;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.Shape;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Line2D;
import java.awt.geom.Path2D;
import java.awt.geom.RoundRectangle2D;

import com.formdev.flatlaf.icons.FlatAbstractIcon;
import com.formdev.flatlaf.ui.FlatUIUtils;

final class StatusIcons {
    private StatusIcons() {
    }

    private static float strokeWidth(float diameter) {
        return Math.max(1f, Math.round(diameter * 0.11f));
    }

    static final class Pass extends FlatAbstractIcon {
        Pass(int size, Color color) {
            super(size, size, color);
        }

        @Override
        protected void paintIcon(Component c, Graphics2D g) {
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            float d = width;
            g.setColor(color);
            g.fill(new Ellipse2D.Float(0, 0, d, d));
            g.setColor(Color.WHITE);
            g.setStroke(new BasicStroke(strokeWidth(d), BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            Path2D check = new Path2D.Float();
            check.moveTo(d * 0.28f, d * 0.52f);
            check.lineTo(d * 0.43f, d * 0.68f);
            check.lineTo(d * 0.73f, d * 0.34f);
            g.draw(check);
        }
    }

    static final class Warn extends FlatAbstractIcon {
        Warn(int size, Color color) {
            super(size, size, color);
        }

        @Override
        protected void paintIcon(Component c, Graphics2D g) {
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            float d = width;

            Shape tri = FlatUIUtils.createRoundTrianglePath(
                d * 0.5f, 0, d, d * 0.875f, 0, d * 0.875f, d * 0.125f);
            g.setColor(color);
            g.fill(tri);

            g.setColor(Color.WHITE);
            float bw = d * 0.125f;
            g.fill(new RoundRectangle2D.Float(d * 0.5f - bw / 2, d * 0.25f, bw, d * 0.34375f, bw, bw));
            g.fill(new Ellipse2D.Float(d * 0.5f - bw / 2, d * 0.65625f, bw, bw));
        }
    }

    static final class Fail extends FlatAbstractIcon {
        Fail(int size, Color color) {
            super(size, size, color);
        }

        @Override
        protected void paintIcon(Component c, Graphics2D g) {
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            float d = width;
            g.setColor(color);
            g.fill(new Ellipse2D.Float(0, 0, d, d));
            g.setColor(Color.WHITE);
            g.setStroke(new BasicStroke(strokeWidth(d), BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g.draw(new Line2D.Float(d * 0.32f, d * 0.32f, d * 0.68f, d * 0.68f));
            g.draw(new Line2D.Float(d * 0.68f, d * 0.32f, d * 0.32f, d * 0.68f));
        }
    }
}
