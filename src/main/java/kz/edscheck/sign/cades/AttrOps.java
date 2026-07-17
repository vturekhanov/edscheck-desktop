package kz.edscheck.sign.cades;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import kz.gov.pki.kalkan.asn1.ASN1EncodableVector;
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;
import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.asn1.cms.AttributeTable;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation;
import kz.gov.pki.kalkan.ocsp.BasicOCSPResp;
import kz.gov.pki.kalkan.tsp.TimeStampToken;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;
import kz.edscheck.online.Online;
import kz.edscheck.parsing.ParsedContainer;
import kz.edscheck.parsing.ParsedSigner;
import kz.edscheck.parsing.Parsing;


public final class AttrOps {
    public enum Attr { TSP, OCSP }

    
    
    
    private static final DERObjectIdentifier OID_SIGNATURE_TS_TOKEN =
        new DERObjectIdentifier("1.2.840.113549.1.9.16.2.14");
    private static final DERObjectIdentifier OID_REVOCATION_VALUES =
        new DERObjectIdentifier("1.2.840.113549.1.9.16.2.24");
    private static final Duration TIMEOUT = Duration.ofSeconds(15);

    
    public record Result(byte[] bytes, boolean changed, List<String> messages) {
    }

    private AttrOps() {
    }

    
    public static Result add(byte[] cmsDer, Set<Attr> targets, boolean force, SignerSelector selector) {
        ParsedContainer parsed = Parsing.parseContainer(cmsDer, List.of());
        List<Integer> indices = selector.resolve(parsed.signers().size());
        requireNoArchiveTimestampAt(parsed, indices, "--add " + describe(targets));

        Map<Integer, SignerInformation> updates = new LinkedHashMap<>();
        List<String> messages = new ArrayList<>();
        boolean multi = indices.size() > 1;

        for (int idx : indices) {
            ParsedSigner ps = parsed.signers().get(idx);
            String prefix = multi ? "#" + idx + ": " : "";
            X509Certificate subject = ps.signerCertRaw();
            if (subject == null) {
                throw new SignException(Messages.get(MsgKey.ATTR_OPS_SIGNER_CERT_NOT_FOUND, prefix));
            }

            boolean atomic = targets.size() > 1;
            if (!force) {
                boolean tspBlocks = targets.contains(Attr.TSP) && ps.hasTimestamp();
                boolean ocspBlocks = targets.contains(Attr.OCSP) && ps.hasRevocationValues();
                if (atomic && (tspBlocks || ocspBlocks)) {
                    if (tspBlocks) {
                        messages.add(Messages.get(MsgKey.ATTR_OPS_TSP_BLOCKS_ATOMIC, prefix));
                    }
                    if (ocspBlocks) {
                        messages.add(Messages.get(MsgKey.ATTR_OPS_OCSP_BLOCKS_ATOMIC, prefix));
                    }
                    continue;
                }
            }

            boolean doTsp = targets.contains(Attr.TSP) && (force || !ps.hasTimestamp());
            boolean doOcsp = targets.contains(Attr.OCSP) && (force || !ps.hasRevocationValues());
            if (targets.contains(Attr.TSP) && !doTsp) {
                messages.add(Messages.get(MsgKey.ATTR_OPS_TSP_ALREADY_PRESENT, prefix));
            }
            if (targets.contains(Attr.OCSP) && !doOcsp) {
                messages.add(Messages.get(MsgKey.ATTR_OPS_OCSP_ALREADY_PRESENT, prefix));
            }
            if (!doTsp && !doOcsp) {
                continue;
            }

            SignerInformation si = ps.signerInfo();
            
            
            if (doTsp) {
                TimeStampToken token = CadesBltBuilder.requestTsaForSignature(
                    si, CadesBltBuilder.TSA_URL, CadesBltBuilder.TSA_REQ_POLICY);
                si = SignerInformation.replaceUnsignedAttributes(
                    si, Online.addSignatureTimestamp(si.getUnsignedAttributes(), token));
                messages.add(Messages.get(force && ps.hasTimestamp()
                    ? MsgKey.ATTR_OPS_TSP_REPLACED : MsgKey.ATTR_OPS_TSP_ADDED, prefix));
            }
            if (doOcsp) {
                X509Certificate issuer = CadesBltBuilder.resolveIssuer(subject);
                BasicOCSPResp basic = Online.requestOcsp(
                    subject, issuer, si.getDigestAlgOID(), CadesBltBuilder.OCSP_URL, TIMEOUT);
                si = SignerInformation.replaceUnsignedAttributes(
                    si, Online.addRevocationValues(si.getUnsignedAttributes(), basic));
                messages.add(Messages.get(force && ps.hasRevocationValues()
                    ? MsgKey.ATTR_OPS_OCSP_REPLACED : MsgKey.ATTR_OPS_OCSP_ADDED, prefix));
            }
            updates.put(idx, si);
        }

        if (updates.isEmpty()) {
            return new Result(cmsDer, false, messages);
        }
        return new Result(CadesBltBuilder.rebuildAtIndices(cmsDer, updates), true, messages);
    }

    
    public static Result strip(byte[] cmsDer, Attr target, SignerSelector selector) {
        ParsedContainer parsed = Parsing.parseContainer(cmsDer, List.of());
        List<Integer> indices = selector.resolve(parsed.signers().size());
        requireNoArchiveTimestampAt(parsed, indices, "--strip " + (target == Attr.TSP ? "tsp" : "ocsp"));

        DERObjectIdentifier oid = target == Attr.TSP ? OID_SIGNATURE_TS_TOKEN : OID_REVOCATION_VALUES;
        MsgKey absentKey = target == Attr.TSP ? MsgKey.ATTR_OPS_TSP_ABSENT : MsgKey.ATTR_OPS_OCSP_ABSENT;
        MsgKey removedKey = target == Attr.TSP ? MsgKey.ATTR_OPS_TSP_REMOVED : MsgKey.ATTR_OPS_OCSP_REMOVED;
        boolean multi = indices.size() > 1;

        Map<Integer, SignerInformation> updates = new LinkedHashMap<>();
        List<String> messages = new ArrayList<>();
        for (int idx : indices) {
            ParsedSigner ps = parsed.signers().get(idx);
            String prefix = multi ? "#" + idx + ": " : "";
            boolean present = target == Attr.TSP ? ps.hasTimestamp() : ps.hasRevocationValues();
            if (!present) {
                messages.add(Messages.get(absentKey, prefix));
                continue;
            }
            SignerInformation si = ps.signerInfo();
            AttributeTable newTable = removeAllByOid(si.getUnsignedAttributes(), oid);
            updates.put(idx, SignerInformation.replaceUnsignedAttributes(si, newTable));
            messages.add(Messages.get(removedKey, prefix));
        }

        if (updates.isEmpty()) {
            return new Result(cmsDer, false, messages);
        }
        return new Result(CadesBltBuilder.rebuildAtIndices(cmsDer, updates), true, messages);
    }

    
    public static Result stripUnsigned(byte[] cmsDer, SignerSelector selector) {
        ParsedContainer parsed = Parsing.parseContainer(cmsDer, List.of());
        List<Integer> indices = selector.resolve(parsed.signers().size());
        boolean multi = indices.size() > 1;

        Map<Integer, SignerInformation> updates = new LinkedHashMap<>();
        List<String> messages = new ArrayList<>();
        for (int idx : indices) {
            ParsedSigner ps = parsed.signers().get(idx);
            String prefix = multi ? "#" + idx + ": " : "";
            SignerInformation si = ps.signerInfo();
            if (si.getUnsignedAttributes() == null) {
                messages.add(Messages.get(MsgKey.ATTR_OPS_UNSIGNED_ABSENT, prefix));
                continue;
            }
            updates.put(idx, SignerInformation.replaceUnsignedAttributes(si, null));
            messages.add(Messages.get(MsgKey.ATTR_OPS_UNSIGNED_STRIPPED, prefix));
        }

        if (updates.isEmpty()) {
            return new Result(cmsDer, false, messages);
        }
        return new Result(CadesBltBuilder.rebuildAtIndices(cmsDer, updates), true, messages);
    }

    

    
    private static void requireNoArchiveTimestampAt(ParsedContainer parsed, List<Integer> indices, String opLabel) {
        List<String> blocked = new ArrayList<>();
        for (int idx : indices) {
            if (parsed.signers().get(idx).archive().count() > 0) {
                blocked.add(String.valueOf(idx));
            }
        }
        if (blocked.isEmpty()) {
            return;
        }
        throw new SignException(Messages.get(MsgKey.ATTR_OPS_ARCHIVE_GUARD,
            String.join(", #", blocked), opLabel));
    }

    private static AttributeTable removeAllByOid(AttributeTable existing, DERObjectIdentifier oid) {
        if (existing == null) {
            return null;
        }
        ASN1EncodableVector vec = new ASN1EncodableVector();
        ASN1EncodableVector old = existing.toASN1EncodableVector();
        for (int i = 0; i < old.size(); i++) {
            Attribute a = Attribute.getInstance(old.get(i));
            if (!a.getAttrType().equals(oid)) {
                vec.add(a);
            }
        }
        return vec.size() == 0 ? null : new AttributeTable(vec);
    }

    private static String describe(Set<Attr> targets) {
        if (targets.equals(EnumSet.of(Attr.TSP, Attr.OCSP))) {
            return "tsp-ocsp";
        }
        return targets.contains(Attr.TSP) ? "tsp" : "ocsp";
    }
}
