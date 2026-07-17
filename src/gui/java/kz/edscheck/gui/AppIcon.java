package kz.edscheck.gui;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URL;

import javax.imageio.ImageIO;


final class AppIcon {
    private AppIcon() {
    }

    static BufferedImage image() {
        return Holder.IMAGE;
    }

    private static BufferedImage load() {
        URL resource = AppIcon.class.getResource("icon.png");
        if (resource == null) {
            throw new IllegalStateException("classpath-ресурс icon.png не найден рядом с kz.edscheck.gui");
        }
        try {
            return ImageIO.read(resource);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static final class Holder {
        static final BufferedImage IMAGE = load();
    }
}
