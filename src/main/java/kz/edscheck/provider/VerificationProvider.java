package kz.edscheck.provider;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import kz.edscheck.domain.DocumentSource;
import kz.edscheck.domain.Stage;
import kz.edscheck.domain.VerificationRequest;
import kz.edscheck.errors.ContainerException;
import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;


public interface VerificationProvider {
    String name();

    
    Set<Stage> capabilities();

    
    ProviderResult verify(VerificationRequest request, byte[] container);

    
    default boolean supportsDetached() {
        return false;
    }

    
    default List<ProviderResult> verifyDdcard(
            VerificationRequest request, DocumentSource document, List<byte[]> signatures) {
        throw new UnsupportedOperationException(
            Messages.get(MsgKey.VERIFICATION_PROVIDER_DETACHED_UNSUPPORTED, name()));
    }

    
    default ProviderResult verifyStreaming(VerificationRequest request, DocumentSource container) {
        byte[] bytes;
        try {
            bytes = container.readAllBytes();
        } catch (IOException e) {
            throw new ContainerException(Messages.get(MsgKey.CONTAINER_READ_FAILED, e.getMessage()), e);
        }
        return verify(request, bytes);
    }
}
