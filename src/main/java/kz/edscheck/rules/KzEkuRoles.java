package kz.edscheck.rules;

import java.util.LinkedHashMap;
import java.util.Map;

import kz.edscheck.msg.Messages;
import kz.edscheck.msg.MsgKey;

public final class KzEkuRoles {

    public static final Map<String, String> ROLES = build();

    private static Map<String, String> build() {
        Map<String, String> m = new LinkedHashMap<>();

        m.put("1.2.398.3.3.4.1.1", Messages.get(MsgKey.KZ_EKU_ROLE_INDIVIDUAL));
        m.put("1.2.398.3.3.4.1.1.1", Messages.get(MsgKey.KZ_EKU_ROLE_INDIVIDUAL_INFO_SYSTEM));
        m.put("1.2.398.3.3.4.1.2", Messages.get(MsgKey.KZ_EKU_ROLE_LEGAL_ENTITY));
        m.put("1.2.398.3.3.4.1.2.1", Messages.get(MsgKey.KZ_EKU_ROLE_CHIEF_EXECUTIVE));
        m.put("1.2.398.3.3.4.1.2.2", Messages.get(MsgKey.KZ_EKU_ROLE_SIGNER));
        m.put("1.2.398.3.3.4.1.2.3", Messages.get(MsgKey.KZ_EKU_ROLE_FINANCIAL_SIGNER));
        m.put("1.2.398.3.3.4.1.2.4", Messages.get(MsgKey.KZ_EKU_ROLE_HR_EMPLOYEE));
        m.put("1.2.398.3.3.4.1.2.5", Messages.get(MsgKey.KZ_EKU_ROLE_ORG_EMPLOYEE));
        m.put("1.2.398.3.3.4.1.2.6", Messages.get(MsgKey.KZ_EKU_ROLE_LEGAL_ENTITY_INFO_SYSTEM));

        m.put("1.2.398.3.17.3.1", Messages.get(MsgKey.KZ_EKU_ROLE_INDIVIDUAL));
        m.put("1.2.398.3.17.3.2", Messages.get(MsgKey.KZ_EKU_ROLE_LEGAL_ENTITY));
        m.put("1.2.398.3.17.3.3", Messages.get(MsgKey.KZ_EKU_ROLE_CHIEF_EXECUTIVE));
        m.put("1.2.398.3.17.3.4", Messages.get(MsgKey.KZ_EKU_ROLE_SIGNER));
        m.put("1.2.398.3.17.3.5", Messages.get(MsgKey.KZ_EKU_ROLE_FINANCIAL_SIGNER));
        m.put("1.2.398.3.17.3.6", Messages.get(MsgKey.KZ_EKU_ROLE_HR_EMPLOYEE));
        m.put("1.2.398.3.17.3.7", Messages.get(MsgKey.KZ_EKU_ROLE_ORG_EMPLOYEE));

        m.put("1.2.398.3.2.3.1", Messages.get(MsgKey.KZ_EKU_ROLE_PRESIDENTIAL_ARCHIVE_EMPLOYEE));
        m.put("1.2.398.3.2.3.2", Messages.get(MsgKey.KZ_EKU_ROLE_CENTRAL_ARCHIVE_EMPLOYEE));
        m.put("1.2.398.3.2.3.3", Messages.get(MsgKey.KZ_EKU_ROLE_DEPARTMENTAL_ARCHIVE_EMPLOYEE));
        m.put("1.2.398.3.2.3.4", Messages.get(MsgKey.KZ_EKU_ROLE_CIVIL_SERVANT));
        return Map.copyOf(m);
    }

    private KzEkuRoles() {
    }
}
