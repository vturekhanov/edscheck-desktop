package kz.edscheck.gui.theme;

import java.awt.Font;

import javax.swing.UIManager;

import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.themes.FlatMacDarkLaf;
import com.formdev.flatlaf.themes.FlatMacLightLaf;
import com.formdev.flatlaf.util.SystemInfo;


public final class ThemeApplier {
    private static final float FONT_SIZE_DELTA = 2f;

    
    private static Float baseFontSize;

    private ThemeApplier() {
    }

    public static void apply(OsTheme theme) {
        if (SystemInfo.isMacOS) {
            if (theme == OsTheme.DARK) {
                FlatMacDarkLaf.setup();
            } else {
                FlatMacLightLaf.setup();
            }
        } else if (theme == OsTheme.DARK) {
            FlatDarkLaf.setup();
        } else {
            FlatLightLaf.setup();
        }

        Font base = UIManager.getFont("defaultFont");
        if (base != null) {
            if (baseFontSize == null) {
                baseFontSize = base.getSize2D();
            }
            UIManager.put("defaultFont", base.deriveFont(baseFontSize + FONT_SIZE_DELTA));
        }
    }
}
