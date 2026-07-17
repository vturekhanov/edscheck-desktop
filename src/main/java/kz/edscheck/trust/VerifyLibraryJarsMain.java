package kz.edscheck.trust;

import java.nio.file.Path;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;


public final class VerifyLibraryJarsMain {
    private VerifyLibraryJarsMain() {
    }

    public static void main(String[] args) {
        Path libDir = Path.of(args.length > 0 ? args[0] : "lib");
        try {
            LibraryJars.verifyAll(libDir);
            System.out.println(Messages.get(MsgKey.VERIFY_LIBRARY_JARS_CONFIRMED, libDir));
        } catch (LibraryJarException e) {
            System.err.println(Messages.get(MsgKey.CLI_ERROR, e.getMessage()));
            System.exit(2);
        }
    }
}
