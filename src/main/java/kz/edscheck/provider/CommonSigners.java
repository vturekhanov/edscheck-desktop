package kz.edscheck.provider;

import java.util.List;
import java.util.Map;
import kz.edscheck.domain.CheckStatus;
import kz.edscheck.domain.Stage;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.parsing.ParsedSigner;

public final class CommonSigners {
    private static final String UNRESOLVED_DETAIL = Messages.get(MsgKey.COMMON_UNRESOLVED_SIGNER_DETAIL);

    private CommonSigners() {
    }

    public static SignerVerification unresolvedSigner(ParsedSigner ps) {
        return new SignerVerification(
            ps.index(), ps.certificate(), ps.keyUsage(),
            new TimestampInfo(ps.hasTimestamp(), null, ps.tstGenTime(), null, null, null),
            ps.archive(),
            Map.of(Stage.CHAIN, new StageOutcome(CheckStatus.FAIL, UNRESOLVED_DETAIL)),
            ps.chain(),
            List.of(),
            ps.missingBbAttrs());
    }
}
