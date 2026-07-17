package kz.edscheck.sign.cades;

import java.util.List;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;


public final class SignerSelector {
    private enum Kind { SINGLE, INDEX, ALL }

    private final Kind kind;
    private final int index;

    private SignerSelector(Kind kind, int index) {
        this.kind = kind;
        this.index = index;
    }

    public static SignerSelector single() {
        return new SignerSelector(Kind.SINGLE, -1);
    }

    public static SignerSelector at(int index) {
        if (index < 0) {
            throw new SignException(Messages.get(MsgKey.SIGN_INDEX_NEGATIVE, index));
        }
        return new SignerSelector(Kind.INDEX, index);
    }

    public static SignerSelector all() {
        return new SignerSelector(Kind.ALL, -1);
    }

    public boolean isAll() {
        return kind == Kind.ALL;
    }

    
    public List<Integer> resolve(int signerCount) {
        return switch (kind) {
            case SINGLE -> {
                if (signerCount != 1) {
                    throw new SignException(
                        Messages.get(MsgKey.SIGNER_SELECTOR_MULTIPLE_SIGNERS_NEED_INDEX, signerCount));
                }
                yield List.of(0);
            }
            case INDEX -> {
                if (index >= signerCount) {
                    throw new SignException(Messages.get(MsgKey.SIGNER_SELECTOR_INDEX_OUT_OF_RANGE,
                        index, signerCount, signerCount - 1));
                }
                yield List.of(index);
            }
            case ALL -> List.copyOf(java.util.stream.IntStream.range(0, signerCount).boxed().toList());
        };
    }

    @Override
    public String toString() {
        return switch (kind) {
            case SINGLE -> Messages.get(MsgKey.SIGNER_SELECTOR_SINGLE_LABEL);
            case INDEX -> "#" + index;
            case ALL -> Messages.get(MsgKey.SIGNER_SELECTOR_ALL_LABEL);
        };
    }
}
