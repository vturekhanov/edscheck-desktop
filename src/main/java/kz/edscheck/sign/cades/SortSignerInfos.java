package kz.edscheck.sign.cades;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import kz.gov.pki.kalkan.asn1.ASN1EncodableVector;
import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.ASN1Set;
import kz.gov.pki.kalkan.asn1.BERSet;
import kz.gov.pki.kalkan.asn1.cms.CMSObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.cms.ContentInfo;
import kz.gov.pki.kalkan.asn1.cms.SignedData;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.parsing.ParsedContainer;
import kz.edscheck.parsing.ParsedSigner;
import kz.edscheck.parsing.Parsing;

public final class SortSignerInfos {
    public enum Criterion { TIME, DER }

    private SortSignerInfos() {
    }

    public static AttrOps.Result sort(byte[] cmsDer, Criterion criterion) {
        ContentInfo outer = parseOuter(cmsDer);
        SignedData signedData = SignedData.getInstance(outer.getContent());
        ASN1Set rawSignerInfos = signedData.getSignerInfos();
        int n = rawSignerInfos.size();

        List<String> messages = new ArrayList<>();
        if (n <= 1) {
            messages.add(Messages.get(MsgKey.SORT_SIGNER_INFOS_NOTHING_TO_SORT, n));
            return new AttrOps.Result(cmsDer, false, messages);
        }

        ParsedContainer parsed = Parsing.parseContainer(cmsDer, List.of());
        if (parsed.signers().size() != n) {
            throw new SignException(
                Messages.get(MsgKey.SORT_SIGNER_INFOS_MISMATCH, parsed.signers().size(), n));
        }
        for (ParsedSigner ps : parsed.signers()) {
            messages.add(Messages.get(MsgKey.SORT_SIGNER_INFOS_LINE_GEN_TIME, ps.index(),
                ps.tstGenTime() != null ? ps.tstGenTime() : Messages.get(MsgKey.SORT_SIGNER_INFOS_NO_TSA_MARK)));
        }

        List<Integer> order;
        String criterionLabel;
        if (criterion == Criterion.TIME) {
            List<Instant> genTimes = new ArrayList<>();
            for (ParsedSigner ps : parsed.signers()) {
                genTimes.add(ps.tstGenTime());
            }
            order = orderByTime(genTimes);
            criterionLabel = Messages.get(MsgKey.SORT_SIGNER_INFOS_CRITERION_TIME);
        } else {
            List<byte[]> encodings = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                encodings.add(rawSignerInfos.getObjectAt(i).getDERObject().getDEREncoded());
            }
            order = orderByDer(encodings);
            criterionLabel = Messages.get(MsgKey.SORT_SIGNER_INFOS_CRITERION_DER);
        }

        if (isIdentity(order)) {
            messages.add(Messages.get(MsgKey.SORT_SIGNER_INFOS_ALREADY_SORTED, criterionLabel));
            return new AttrOps.Result(cmsDer, false, messages);
        }
        messages.add(Messages.get(MsgKey.SORT_SIGNER_INFOS_NEW_ORDER, criterionLabel, order));

        ASN1EncodableVector vec = new ASN1EncodableVector();
        for (int idx : order) {
            vec.add(rawSignerInfos.getObjectAt(idx));
        }

        ASN1Set newSignerInfos = new BERSet(vec);
        SignedData newSignedData = new SignedData(
            signedData.getDigestAlgorithms(), signedData.getEncapContentInfo(),
            signedData.getCertificates(), signedData.getCRLs(), newSignerInfos);
        ContentInfo newOuter = new ContentInfo(CMSObjectIdentifiers.signedData, newSignedData);
        return new AttrOps.Result(newOuter.getDEREncoded(), true, messages);
    }

    private static List<Integer> orderByTime(List<Instant> genTimes) {
        List<Integer> indices = new ArrayList<>();
        for (int i = 0; i < genTimes.size(); i++) {
            indices.add(i);
        }
        indices.sort((i, j) -> {
            Instant a = genTimes.get(i);
            Instant b = genTimes.get(j);
            if (a == null && b == null) {
                return 0;
            }
            if (a == null) {
                return 1;
            }
            if (b == null) {
                return -1;
            }
            return a.compareTo(b);
        });
        return indices;
    }

    private static List<Integer> orderByDer(List<byte[]> encodings) {
        int maxLen = 0;
        for (byte[] e : encodings) {
            maxLen = Math.max(maxLen, e.length);
        }
        List<byte[]> padded = new ArrayList<>();
        for (byte[] e : encodings) {
            padded.add(Arrays.copyOf(e, maxLen)); 
        }
        List<Integer> indices = new ArrayList<>();
        for (int i = 0; i < encodings.size(); i++) {
            indices.add(i);
        }
        indices.sort((i, j) -> compareUnsigned(padded.get(i), padded.get(j)));
        return indices;
    }

    private static int compareUnsigned(byte[] a, byte[] b) {
        for (int i = 0; i < a.length; i++) {
            int x = a[i] & 0xFF;
            int y = b[i] & 0xFF;
            if (x != y) {
                return Integer.compare(x, y);
            }
        }
        return 0;
    }

    private static boolean isIdentity(List<Integer> order) {
        for (int i = 0; i < order.size(); i++) {
            if (order.get(i) != i) {
                return false;
            }
        }
        return true;
    }

    private static ContentInfo parseOuter(byte[] der) {
        try {
            return ContentInfo.getInstance(new ASN1InputStream(der).readObject());
        } catch (Exception e) {
            throw new SignException(Messages.get(MsgKey.CONTAINER_PARSE_CMS_FAILED, e.getMessage()));
        }
    }
}
