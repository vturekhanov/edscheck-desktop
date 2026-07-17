package kz.edscheck.msg;


public enum MsgKey {
    
    TEXT_HEADER("text.header", 0),
    TEXT_FILE_LINE("text.file_line", 3),
    TEXT_FORMAT_DDCARD("text.format_ddcard", 0),
    TEXT_FORMAT_DDCARD_DOC("text.format_ddcard_doc", 1),
    TEXT_FORMAT_DETACHED("text.format_detached", 0),
    TEXT_FORMAT_DETACHED_DOC("text.format_detached_doc", 1),
    TEXT_SIGNATURES_TOTAL("text.signatures_total", 1),
    TEXT_SIGNATURE_HEADER("text.signature_header", 2),

    
    VERDICT_GENUINE("verdict.genuine", 0),
    VERDICT_GENUINE_WARNINGS("verdict.genuine_warnings", 0),
    VERDICT_INVALID("verdict.invalid", 0),

    
    LABEL_SIGNER("label.signer", 0),
    LABEL_IIN("label.iin", 0),
    LABEL_BIN("label.bin", 0),
    LABEL_ROLE("label.role", 0),
    LABEL_ORGANIZATION("label.organization", 0),
    LABEL_CERTIFICATE("label.certificate", 0),
    LABEL_REFERENCE_TIME("label.reference_time", 0),
    LABEL_CHECKS("label.checks", 0),
    LABEL_CA("label.ca", 0),

    
    CERT_SERIAL("cert.serial", 1),
    CERT_ISSUER("cert.issuer", 1),
    CERT_VALIDITY_FROM_TO("cert.validity_from_to", 2),
    CERT_VALIDITY_TO("cert.validity_to", 1),
    CERT_VALIDITY_FROM("cert.validity_from", 1),

    
    
    GLYPH_PASS("glyph.pass", 0),
    GLYPH_WARN("glyph.warn", 0),
    GLYPH_FAIL("glyph.fail", 0),
    GLYPH_SKIP("glyph.skip", 0),
    
    CHECK_ONLINE_MARK("check.online_mark", 0),
    
    
    TEXT_NO_VALUE("text.no_value", 0),

    
    CHECK_CRL_HINT("check.crl_hint", 1),
    CHECK_TIMESTAMP_VALID("check.timestamp_valid", 0),
    CHECK_ARCHIVE_TIMESTAMP_VALID("check.archive_timestamp_valid", 0),
    CHECK_KEY_USAGE_PASS("check.key_usage_pass", 0),
    CHECK_REVOCATION_NOT_REVOKED("check.revocation_not_revoked", 0),
    CHECK_REVOCATION_NOT_REVOKED_SRC("check.revocation_not_revoked_src", 1),
    CHECK_REVOCATION_REVOKED("check.revocation_revoked", 0),
    CHECK_REVOCATION_REVOKED_SRC("check.revocation_revoked_src", 1),
    CHECK_REVOCATION_REVOKED_AFTER_REF("check.revocation_revoked_after_ref", 0),
    CHECK_REVOCATION_NOT_VERIFIED("check.revocation_not_verified", 0),

    
    TIME_SOURCE_TIMESTAMP("time_source.timestamp", 0),
    TIME_SOURCE_CURRENT("time_source.current", 0),

    
    STAGE_INTEGRITY("stage.integrity", 0),
    STAGE_SIGNED_ATTRIBUTES("stage.signed_attributes", 0),
    STAGE_TIMESTAMP("stage.timestamp", 0),
    STAGE_CHAIN("stage.chain", 0),
    STAGE_KEY_USAGE("stage.key_usage", 0),
    STAGE_VALIDITY("stage.validity", 0),
    STAGE_REVOCATION("stage.revocation", 0),
    STAGE_ARCHIVE_TIMESTAMP("stage.archive_timestamp", 0),

    
    KEY_ALG_RSA("key_alg.rsa", 0),
    KEY_ALG_GOST("key_alg.gost", 0),

    
    CA_NCA("ca.nca", 0),
    CA_BTSD("ca.btsd", 0),
    CA_UCGO("ca.ucgo", 0),
    CA_UNKNOWN("ca.unknown", 0),
    CA_MIXED("ca.mixed", 0),

    
    REV_SOURCE_OCSP("rev_source.ocsp", 0),
    REV_SOURCE_CRL_EMBEDDED("rev_source.crl_embedded", 0),
    REV_SOURCE_CRL_FILE("rev_source.crl_file", 0),
    REV_SOURCE_CRL_REFERENCE("rev_source.crl_reference", 0),

    
    REVOCATION_REASON_UNSPECIFIED("revocation_reason.unspecified", 0),
    REVOCATION_REASON_KEY_COMPROMISE("revocation_reason.key_compromise", 0),
    REVOCATION_REASON_CA_COMPROMISE("revocation_reason.ca_compromise", 0),
    REVOCATION_REASON_AFFILIATION_CHANGED("revocation_reason.affiliation_changed", 0),
    REVOCATION_REASON_SUPERSEDED("revocation_reason.superseded", 0),
    REVOCATION_REASON_CESSATION_OF_OPERATION("revocation_reason.cessation_of_operation", 0),
    REVOCATION_REASON_CERTIFICATE_HOLD("revocation_reason.certificate_hold", 0),
    REVOCATION_REASON_REMOVE_FROM_CRL("revocation_reason.remove_from_crl", 0),
    REVOCATION_REASON_PRIVILEGE_WITHDRAWN("revocation_reason.privilege_withdrawn", 0),
    REVOCATION_REASON_AA_COMPROMISE("revocation_reason.aa_compromise", 0),

    
    RULES_TIMESTAMP_REQUIRED_ABSENT("rules.timestamp_required_absent", 0),
    RULES_TIMESTAMP_ABSENT_WARN("rules.timestamp_absent_warn", 0),
    RULES_TIMESTAMP_TSA_NO_EKU("rules.timestamp_tsa_no_eku", 0),
    RULES_TIMESTAMP_TSA_OCSP_WINDOW("rules.timestamp_tsa_ocsp_window", 0),
    RULES_TIMESTAMP_INVALID("rules.timestamp_invalid", 0),
    RULES_SIGNED_ATTRS_REQUIRED_MISSING("rules.signed_attrs_required_missing", 1),
    RULES_SIGNED_ATTRS_MISSING("rules.signed_attrs_missing", 1),
    RULES_ARCHIVE_TS_LEGACY_UNSUPPORTED("rules.archive_ts_legacy_unsupported", 0),
    RULES_ARCHIVE_TS_NONE("rules.archive_ts_none", 0),
    RULES_ARCHIVE_TS_PROVIDER_UNSUPPORTED("rules.archive_ts_provider_unsupported", 0),
    RULES_VALIDITY_UNDETERMINED("rules.validity_undetermined", 1),
    RULES_VALIDITY_BEFORE_NOT_BEFORE("rules.validity_before_not_before", 1),
    RULES_VALIDITY_EXPIRED("rules.validity_expired", 1),
    RULES_REVOCATION_SOURCE_CRL("rules.revocation_source_crl", 0),
    RULES_REVOCATION_SOURCE_OCSP_RECEIPT("rules.revocation_source_ocsp_receipt", 0),
    RULES_REVOCATION_NO_THIS_UPDATE("rules.revocation_no_this_update", 1),
    RULES_REVOCATION_CRL_NO_NEXT_UPDATE("rules.revocation_crl_no_next_update", 0),
    RULES_REVOCATION_CRL_INVALID_NOW("rules.revocation_crl_invalid_now", 0),
    RULES_REVOCATION_OCSP_WINDOW_VIOLATED("rules.revocation_ocsp_window_violated", 0),
    RULES_KEY_USAGE_NO_DATA("rules.key_usage_no_data", 0),
    RULES_KEY_USAGE_NO_NON_REPUDIATION("rules.key_usage_no_non_repudiation", 0),
    RULES_KEY_USAGE_NOT_FOR_SIGNING("rules.key_usage_not_for_signing", 0),

    
    PROVIDER_TRACE_ANCHOR_BOUND("provider.trace_anchor_bound", 0),
    PROVIDER_TRACE_ANCHOR_BOUND_WITH_CA("provider.trace_anchor_bound_with_ca", 1),
    PROVIDER_TRACE_ANCHOR_NOT_BOUND("provider.trace_anchor_not_bound", 1),
    PROVIDER_ANCHOR_SELF_SIGNED_MISMATCH("provider.anchor_self_signed_mismatch", 0),
    PROVIDER_ANCHOR_ROOT_NOT_TRUSTED("provider.anchor_root_not_trusted", 0),
    PROVIDER_ANCHOR_ISSUER_NOT_FOUND_FILE("provider.anchor_issuer_not_found_file", 0),
    PROVIDER_ANCHOR_ISSUER_NOT_FOUND("provider.anchor_issuer_not_found", 0),
    PROVIDER_ANCHOR_CYCLE("provider.anchor_cycle", 0),
    PROVIDER_ISSUERS_UNKNOWN("provider.issuers_unknown", 0),
    PROVIDER_SIGNER_CERT_REASON_UNKNOWN_CA("provider.signer_cert_reason_unknown_ca", 0),
    PROVIDER_SIGNER_CERT_REASON_WRONG_CA("provider.signer_cert_reason_wrong_ca", 1),
    PROVIDER_SIGNER_CERT_REJECTED("provider.signer_cert_rejected", 2),
    PROVIDER_TRACE_UNRESOLVED_SIGNER("provider.trace_unresolved_signer", 0),
    PROVIDER_TRACE_BB_ATTRS_OK("provider.trace_bb_attrs_ok", 0),
    PROVIDER_TRACE_BB_ATTRS_MISSING("provider.trace_bb_attrs_missing", 1),
    PROVIDER_CHAIN_NOT_ANCHORED("provider.chain_not_anchored", 0),
    PROVIDER_TRACE_INTEGRITY_OK("provider.trace_integrity_ok", 0),
    PROVIDER_TRACE_INTEGRITY_MISMATCH("provider.trace_integrity_mismatch", 0),
    PROVIDER_INTEGRITY_MISMATCH("provider.integrity_mismatch", 0),
    PROVIDER_TRACE_INTEGRITY_ERROR("provider.trace_integrity_error", 1),
    PROVIDER_TRACE_ESS_UNKNOWN_ALG("provider.trace_ess_unknown_alg", 1),
    PROVIDER_ESS_UNKNOWN_ALG("provider.ess_unknown_alg", 1),
    PROVIDER_TRACE_ESS_HASH_MISMATCH("provider.trace_ess_hash_mismatch", 1),
    PROVIDER_ESS_HASH_MISMATCH("provider.ess_hash_mismatch", 0),
    PROVIDER_TRACE_ESS_HASH_MATCH("provider.trace_ess_hash_match", 1),
    PROVIDER_TRACE_ESS_ERROR("provider.trace_ess_error", 1),
    PROVIDER_ESS_CHECK_ERROR("provider.ess_check_error", 1),
    PROVIDER_TRACE_CHAIN_BUILT("provider.trace_chain_built", 0),
    PROVIDER_TRACE_CHAIN_NOT_BUILT("provider.trace_chain_not_built", 1),
    PROVIDER_TIMESTAMP_NO_TST_ATTR("provider.timestamp_no_tst_attr", 0),
    PROVIDER_TRACE_TST_SIGNATURE_OK("provider.trace_tst_signature_ok", 1),
    PROVIDER_TRACE_TST_SIGNATURE_FAIL("provider.trace_tst_signature_fail", 1),
    PROVIDER_TRACE_TST_BINDING_OK("provider.trace_tst_binding_ok", 1),
    PROVIDER_TRACE_TST_BINDING_FAIL("provider.trace_tst_binding_fail", 1),
    PROVIDER_TRACE_TSA_CHAIN_OK("provider.trace_tsa_chain_ok", 0),
    PROVIDER_TRACE_TSA_CHAIN_FAIL("provider.trace_tsa_chain_fail", 1),
    PROVIDER_TIMESTAMP_SIG_FAILED("provider.timestamp_sig_failed", 0),
    PROVIDER_TIMESTAMP_BINDING_FAILED("provider.timestamp_binding_failed", 0),
    PROVIDER_TIMESTAMP_PARSE_FAILED("provider.timestamp_parse_failed", 1),
    PROVIDER_TRACE_TST_PARSE_FAILED("provider.trace_tst_parse_failed", 1),
    PROVIDER_TRACE_TSA_VALIDITY_OK("provider.trace_tsa_validity_ok", 1),
    PROVIDER_TRACE_TSA_VALIDITY_FAIL("provider.trace_tsa_validity_fail", 1),
    PROVIDER_TIMESTAMP_CERT_EXPIRED("provider.timestamp_cert_expired", 0),
    PROVIDER_TIMESTAMP_TSA_OCSP_PREFIX("provider.timestamp_tsa_ocsp_prefix", 1),
    PROVIDER_REVOCATION_NO_OCSP_NO_CRL("provider.revocation_no_ocsp_no_crl", 0),
    PROVIDER_TRACE_OCSP_NOT_EXTRACTED("provider.trace_ocsp_not_extracted", 0),
    PROVIDER_REVOCATION_OCSP_NOT_EXTRACTED("provider.revocation_ocsp_not_extracted", 0),
    PROVIDER_TRACE_OCSP_RESPONDER_MISSING("provider.trace_ocsp_responder_missing", 0),
    PROVIDER_REVOCATION_OCSP_RESPONDER_MISSING("provider.revocation_ocsp_responder_missing", 0),
    PROVIDER_TRACE_OCSP_SIGNATURE_FAILED("provider.trace_ocsp_signature_failed", 0),
    PROVIDER_REVOCATION_OCSP_SIGNATURE_FAILED("provider.revocation_ocsp_signature_failed", 0),
    PROVIDER_TRACE_OCSP_SIGNATURE_OK("provider.trace_ocsp_signature_ok", 0),
    PROVIDER_TRACE_OCSP_RESPONDER_UNAUTHORIZED("provider.trace_ocsp_responder_unauthorized", 0),
    PROVIDER_REVOCATION_OCSP_RESPONDER_UNAUTHORIZED("provider.revocation_ocsp_responder_unauthorized", 0),
    PROVIDER_TRACE_OCSP_RESPONDER_CHAIN_FAILED("provider.trace_ocsp_responder_chain_failed", 1),
    PROVIDER_REVOCATION_OCSP_CHAIN_PREFIX("provider.revocation_ocsp_chain_prefix", 1),
    PROVIDER_TRACE_OCSP_RESPONDER_AUTHORIZED("provider.trace_ocsp_responder_authorized", 1),
    PROVIDER_TRACE_OCSP_ISSUER_NOT_FOUND("provider.trace_ocsp_issuer_not_found", 0),
    PROVIDER_REVOCATION_OCSP_ISSUER_NOT_FOUND("provider.revocation_ocsp_issuer_not_found", 0),
    PROVIDER_TRACE_OCSP_CERTID_MISMATCH("provider.trace_ocsp_certid_mismatch", 0),
    PROVIDER_REVOCATION_OCSP_CERTID_MISMATCH("provider.revocation_ocsp_certid_mismatch", 0),
    PROVIDER_TRACE_OCSP_CERTID_MATCH("provider.trace_ocsp_certid_match", 0),
    PROVIDER_TRACE_OCSP_STATUS_GOOD("provider.trace_ocsp_status_good", 2),
    PROVIDER_REVOCATION_OCSP_GOOD("provider.revocation_ocsp_good", 0),
    PROVIDER_TRACE_OCSP_STATUS_REVOKED("provider.trace_ocsp_status_revoked", 2),
    PROVIDER_REVOCATION_OCSP_REVOKED("provider.revocation_ocsp_revoked", 0),
    PROVIDER_TRACE_OCSP_STATUS_UNKNOWN("provider.trace_ocsp_status_unknown", 0),
    PROVIDER_REVOCATION_OCSP_STATUS_UNKNOWN("provider.revocation_ocsp_status_unknown", 0),
    PROVIDER_TRACE_OCSP_PARSE_FAILED("provider.trace_ocsp_parse_failed", 1),
    PROVIDER_REVOCATION_OCSP_PARSE_FAILED("provider.revocation_ocsp_parse_failed", 1),
    PROVIDER_TRACE_CRL_ISSUER_NOT_FOUND("provider.trace_crl_issuer_not_found", 1),
    PROVIDER_REVOCATION_CRL_ISSUER_NOT_FOUND("provider.revocation_crl_issuer_not_found", 0),
    PROVIDER_TRACE_CRL_SIGNATURE_FAILED("provider.trace_crl_signature_failed", 2),
    PROVIDER_REVOCATION_CRL_SIGNATURE_FAILED("provider.revocation_crl_signature_failed", 1),
    PROVIDER_TRACE_CRL_SIGNATURE_OK("provider.trace_crl_signature_ok", 1),
    PROVIDER_TRACE_CRL_REVOKED("provider.trace_crl_revoked", 1),
    PROVIDER_REVOCATION_CRL_REVOKED("provider.revocation_crl_revoked", 0),
    PROVIDER_TRACE_CRL_NOT_REVOKED("provider.trace_crl_not_revoked", 0),
    PROVIDER_TRACE_CRL_PARSE_FAILED("provider.trace_crl_parse_failed", 2),
    PROVIDER_REVOCATION_CRL_PARSE_FAILED("provider.revocation_crl_parse_failed", 1),
    PROVIDER_TRACE_ARCHIVE_MARK("provider.trace_archive_mark", 2),
    PROVIDER_TRACE_ARCHIVE_MARK_OK("provider.trace_archive_mark_ok", 0),
    PROVIDER_LABEL_SIGNATURE("provider.label_signature", 1),
    PROVIDER_LABEL_TSA_CERT_SUFFIX("provider.label_tsa_cert_suffix", 0),
    PROVIDER_TRACE_REVOCATION_PREFIX("provider.trace_revocation_prefix", 1),

    
    COMMON_FOREIGN_SIGNATURE_DETAIL("common.foreign_signature_detail", 0),
    COMMON_UNRESOLVED_SIGNER_DETAIL("common.unresolved_signer_detail", 0),

    
    CONTAINER_READ_FAILED("container.read_failed", 1),
    CONTAINER_DOCUMENT_READ_FAILED("container.document_read_failed", 1),
    CONTAINER_PARSE_CMS_FAILED("container.parse_cms_failed", 1),

    
    ENGINE_PROVIDER_STAGE_UNSUPPORTED("engine.provider_stage_unsupported", 0),
    ENGINE_STAGE_NO_RESULT("engine.stage_no_result", 0),

    
    ONLINE_TRACE_SIGNER_CERT_MISSING("online.trace_signer_cert_missing", 1),
    ONLINE_TRACE_ISSUER_MISSING("online.trace_issuer_missing", 1),
    ONLINE_TRACE_ENDPOINT_UNSUPPORTED("online.trace_endpoint_unsupported", 1),
    ONLINE_TRACE_SKIP("online.trace_skip", 2),
    ONLINE_TRACE_OCSP_REQUEST("online.trace_ocsp_request", 3),
    ONLINE_OCSP_URL_NOT_FOUND("online.ocsp_url_not_found", 0),
    ONLINE_TRACE_REVOCATION_VALUES_ADDED("online.trace_revocation_values_added", 1),
    ONLINE_REVOCATION_VALUES_INSERT_FAILED("online.revocation_values_insert_failed", 1),
    ONLINE_OCSP_REQUEST_BUILD_FAILED("online.ocsp_request_build_failed", 1),
    ONLINE_OCSP_REQUEST_FAILED("online.ocsp_request_failed", 1),
    ONLINE_OCSP_RESPONDER_STATUS("online.ocsp_responder_status", 1),
    ONLINE_OCSP_UNEXPECTED_RESPONSE_TYPE("online.ocsp_unexpected_response_type", 1),
    ONLINE_OCSP_RESPONSE_PARSE_FAILED("online.ocsp_response_parse_failed", 1),
    ONLINE_REVOCATION_VALUES_BUILD_FAILED("online.revocation_values_build_failed", 1),
    ONLINE_OCSP_NONCE_MISMATCH("online.ocsp_nonce_mismatch", 0),
    ONLINE_EMBEDDED_OCSP_PARSE_FAILED("online.embedded_ocsp_parse_failed", 1),
    ONLINE_TRACE_TSA_REQUEST("online.trace_tsa_request", 3),
    ONLINE_TRACE_TST_ADDED("online.trace_tst_added", 1),
    ONLINE_TST_INSERT_FAILED("online.tst_insert_failed", 1),
    ONLINE_UNKNOWN_DIGEST_ALG("online.unknown_digest_alg", 1),
    ONLINE_SIGNATURE_VALUE_MISSING("online.signature_value_missing", 0),
    ONLINE_IMPRINT_COMPUTE_FAILED("online.imprint_compute_failed", 1),
    ONLINE_TSA_REQUEST_FAILED("online.tsa_request_failed", 1),
    ONLINE_TSA_STATUS("online.tsa_status", 2),
    ONLINE_TSA_NO_TOKEN("online.tsa_no_token", 1),
    ONLINE_TSA_RESPONSE_PARSE_FAILED("online.tsa_response_parse_failed", 1),
    ONLINE_TST_BUILD_FAILED("online.tst_build_failed", 1),
    ONLINE_HTTP_ERROR("online.http_error", 2),
    ONLINE_TRACE_AUGMENTED_COUNT("online.trace_augmented_count", 2),
    ONLINE_MERGE_GAP("online.merge_gap", 1),

    
    PARSING_CERTS_READ_FAILED("parsing.certs_read_failed", 1),
    PARSING_NO_SIGNERS("parsing.no_signers", 0),
    PARSING_BIND_DIGEST_FAILED("parsing.bind_digest_failed", 1),
    PARSING_PEM_NO_BEGIN("parsing.pem_no_begin", 0),
    PARSING_PEM_BAD_HEADER("parsing.pem_bad_header", 0),
    PARSING_PEM_NO_END("parsing.pem_no_end", 0),

    
    ARCHIVE_TS_TST_PARSE_FAILED("archive_ts.tst_parse_failed", 1),
    ARCHIVE_TS_NO_ATS_HASH_INDEX("archive_ts.no_ats_hash_index", 0),
    ARCHIVE_TS_ATS_HASH_INDEX_PARSE_FAILED("archive_ts.ats_hash_index_parse_failed", 1),
    ARCHIVE_TS_IMPRINT_NO_MESSAGE_DIGEST("archive_ts.imprint_no_message_digest", 0),
    ARCHIVE_TS_CERT_HASHES_MISMATCH("archive_ts.cert_hashes_mismatch", 0),
    ARCHIVE_TS_CRL_HASHES_MISMATCH("archive_ts.crl_hashes_mismatch", 0),
    ARCHIVE_TS_ATTR_HASHES_MISMATCH("archive_ts.attr_hashes_mismatch", 0),
    ARCHIVE_TS_IMPRINT_NOT_RECOMPUTED("archive_ts.imprint_not_recomputed", 0),
    ARCHIVE_TS_IMPRINT_MISMATCH("archive_ts.imprint_mismatch", 0),
    ARCHIVE_TS_TST_SIGNATURE_UNCONFIRMED("archive_ts.tst_signature_unconfirmed", 0),
    ARCHIVE_TS_TSA_CHAIN_NOT_ANCHORED("archive_ts.tsa_chain_not_anchored", 0),
    ARCHIVE_TS_TSA_CERT_EXPIRED("archive_ts.tsa_cert_expired", 0),
    ARCHIVE_TS_TSA_NO_TIMESTAMPING_EKU("archive_ts.tsa_no_timestamping_eku", 0),
    ARCHIVE_TS_MARK_FAILURE("archive_ts.mark_failure", 3),
    ARCHIVE_TS_ALL_VALID("archive_ts.all_valid", 1),

    
    DDCARD_NOT_PDF("ddcard.not_pdf", 0),
    DDCARD_NO_EMBEDDED_FILES("ddcard.no_embedded_files", 0),
    DDCARD_NO_SIGNATURES("ddcard.no_signatures", 0),
    DDCARD_PARSE_FAILED("ddcard.parse_failed", 1),
    DDCARD_RECONSTRUCT_FAILED("ddcard.reconstruct_failed", 1),
    DDCARD_ATTACHMENT_NOT_FOUND("ddcard.attachment_not_found", 1),
    DDCARD_ATTACHMENT_NO_EF_STREAM("ddcard.attachment_no_ef_stream", 0),
    DDCARD_ATTACHMENT_OPEN_FAILED("ddcard.attachment_open_failed", 2),

    
    KALKAN_JAR_PATH_PROPERTY_MISSING("kalkan_jar.path_property_missing", 1),
    KALKAN_JAR_NOT_FOUND("kalkan_jar.not_found", 1),
    KALKAN_JAR_SHA256_COMPUTE_FAILED("kalkan_jar.sha256_compute_failed", 2),
    KALKAN_JAR_SHA256_MISMATCH("kalkan_jar.sha256_mismatch", 3),

    
    LIBRARY_JARS_PATH_PROPERTY_MISSING("library_jars.path_property_missing", 1),
    LIBRARY_JARS_NOT_FOUND("library_jars.not_found", 1),
    LIBRARY_JARS_SHA256_COMPUTE_FAILED("library_jars.sha256_compute_failed", 2),
    LIBRARY_JARS_SHA256_MISMATCH("library_jars.sha256_mismatch", 3),

    
    MANIFEST_TRUST_TRUSTED_CERT_NOT_FOUND("manifest_trust.trusted_cert_not_found", 1),
    MANIFEST_TRUST_READ_FAILED("manifest_trust.read_failed", 2),
    MANIFEST_TRUST_PARSE_FAILED("manifest_trust.parse_failed", 2),
    MANIFEST_TRUST_CERT_FACTORY_FAILED("manifest_trust.cert_factory_failed", 1),
    MANIFEST_TRUST_CERT_PARSE_FAILED("manifest_trust.cert_parse_failed", 1),

    
    
    ATTACHED_SPLITTER_WRONG_CONTENT_TYPE("attached_splitter.wrong_content_type", 1),
    ATTACHED_SPLITTER_ECONTENT_ABSENT("attached_splitter.econtent_absent", 0),
    ATTACHED_SPLITTER_ECONTENT_NOT_OCTET_STRING("attached_splitter.econtent_not_octet_string", 1),
    ATTACHED_SPLITTER_ENCAP_LENGTH_MISMATCH("attached_splitter.encap_length_mismatch", 0),
    ATTACHED_SPLITTER_TAIL_UNEXPECTED_SIZE("attached_splitter.tail_unexpected_size", 1),
    ATTACHED_SPLITTER_TAIL_INDEFINITE_TOO_LARGE("attached_splitter.tail_indefinite_too_large", 0),
    ATTACHED_SPLITTER_UNEXPECTED_ASN1_TYPE("attached_splitter.unexpected_asn1_type", 2),
    ATTACHED_SPLITTER_FIELD_PARSE_FAILED("attached_splitter.field_parse_failed", 1),
    ATTACHED_SPLITTER_CHUNK_OUT_OF_BOUNDS("attached_splitter.chunk_out_of_bounds", 0),
    ATTACHED_SPLITTER_UNEXPECTED_EOF_ECONTENT("attached_splitter.unexpected_eof_econtent", 0),
    ATTACHED_SPLITTER_UNEXPECTED_EOF_TLV("attached_splitter.unexpected_eof_tlv", 0),
    ATTACHED_SPLITTER_MULTIBYTE_TAG_UNSUPPORTED("attached_splitter.multibyte_tag_unsupported", 0),
    ATTACHED_SPLITTER_INDEFINITE_LENGTH_PRIMITIVE("attached_splitter.indefinite_length_primitive", 0),
    ATTACHED_SPLITTER_UNSUPPORTED_LENGTH_FORM("attached_splitter.unsupported_length_form", 0),
    ATTACHED_SPLITTER_LENGTH_TOO_LARGE("attached_splitter.length_too_large", 0),
    ATTACHED_SPLITTER_EXPECTED_EOC("attached_splitter.expected_eoc", 0),
    ATTACHED_SPLITTER_FIELD_TOO_LARGE("attached_splitter.field_too_large", 1),
    ATTACHED_SPLITTER_FIELD_INDEFINITE_TOO_LARGE("attached_splitter.field_indefinite_too_large", 0),
    ATTACHED_SPLITTER_READ_TOO_LARGE("attached_splitter.read_too_large", 1),
    ATTACHED_SPLITTER_UNEXPECTED_EOF_READING_TLV("attached_splitter.unexpected_eof_reading_tlv", 1),
    ATTACHED_SPLITTER_EXPECTED_CLOSING_EOC("attached_splitter.expected_closing_eoc", 0),
    ATTACHED_SPLITTER_EXPECT_CONTENT_INFO_SEQUENCE("attached_splitter.expect_content_info_sequence", 0),
    ATTACHED_SPLITTER_EXPECT_CONTENT_TYPE_OID("attached_splitter.expect_content_type_oid", 0),
    ATTACHED_SPLITTER_EXPECT_EXPLICIT0_CONTENT("attached_splitter.expect_explicit0_content", 0),
    ATTACHED_SPLITTER_EXPECT_SIGNED_DATA_SEQUENCE("attached_splitter.expect_signed_data_sequence", 0),
    ATTACHED_SPLITTER_EXPECT_VERSION("attached_splitter.expect_version", 0),
    ATTACHED_SPLITTER_EXPECT_DIGEST_ALGORITHMS("attached_splitter.expect_digest_algorithms", 0),
    ATTACHED_SPLITTER_EXPECT_ENCAP_CONTENT_INFO("attached_splitter.expect_encap_content_info", 0),
    ATTACHED_SPLITTER_EXPECT_ECONTENT_TYPE("attached_splitter.expect_econtent_type", 0),
    ATTACHED_SPLITTER_EXPECT_ECONTENT_WRAPPER("attached_splitter.expect_econtent_wrapper", 0),
    ATTACHED_SPLITTER_TAG_MISMATCH("attached_splitter.tag_mismatch", 3),

    
    JSON_TRAILING_DATA("json.trailing_data", 1),
    JSON_EXPECTED_COMMA_OR_CLOSE_BRACE("json.expected_comma_or_close_brace", 1),
    JSON_EXPECTED_COMMA_OR_CLOSE_BRACKET("json.expected_comma_or_close_bracket", 1),
    JSON_UNKNOWN_ESCAPE("json.unknown_escape", 1),
    JSON_EXPECTED_LITERAL("json.expected_literal", 2),
    JSON_EXPECTED_CHAR("json.expected_char", 2),

    
    CLI_ERROR("cli.error", 1),
    CLI_FLAG_REQUIRES_VALUE("cli.flag_requires_value", 1),
    CLI_UNKNOWN_FLAG("cli.unknown_flag", 1),
    CLI_EXTRA_POSITIONAL_ARG("cli.extra_positional_arg", 1),
    CLI_FILE_READ_FAILED("cli.file_read_failed", 1),
    CLI_FILE_READ_WRITE_FAILED("cli.file_read_write_failed", 1),
    
    
    CLI_INVALID_LANG("cli.invalid_lang", 2),

    
    MAIN_BATCH_WITH_POSITIONAL("main.batch_with_positional", 0),
    MAIN_CONTAINER_REQUIRED("main.container_required", 0),
    MAIN_INTEGRITY_TEST_COMBINED_UNSUPPORTED("main.integrity_test_combined_unsupported", 0),
    MAIN_BATCH_MANIFEST_READ_FAILED("main.batch_manifest_read_failed", 1),
    MAIN_BATCH_MANIFEST_NOT_ARRAY("main.batch_manifest_not_array", 0),
    MAIN_BATCH_ENTRY_NOT_OBJECT("main.batch_entry_not_object", 0),
    MAIN_BATCH_ENTRY_NO_CONTAINER("main.batch_entry_no_container", 0),
    MAIN_ONLINE_REQUIRES_FULL_BYTES("main.online_requires_full_bytes", 3),
    MAIN_DDCARD_TOO_LARGE("main.ddcard_too_large", 3),
    MAIN_INVALID_ENV("main.invalid_env", 1),
    MAIN_INVALID_ENGINE("main.invalid_engine", 1),
    MAIN_INVALID_FORMAT("main.invalid_format", 1),

    
    
    MAIN_VERSION_LINE("main.version_line", 1),
    MAIN_VERBOSE_PREFIX("main.verbose_prefix", 1),

    
    HASH_FILE_REQUIRED("hash.file_required", 0),
    HASH_INVALID_ALGO("hash.invalid_algo", 2),
    HASH_ALGO_UNSUPPORTED("hash.algo_unsupported", 2),
    HASH_FILE_READ_FAILED("hash.file_read_failed", 2),
    HASH_LINE_FILE("hash.line_file", 2),
    HASH_LINE_ALGORITHM("hash.line_algorithm", 2),
    HASH_LINE_LIBRARY("hash.line_library", 1),
    
    HASH_LIB_LABEL("hash.lib_label", 1),
    HASH_LINE_HASH_HEX("hash.line_hash_hex", 1),
    HASH_LINE_HASH_BASE64("hash.line_hash_base64", 1),
    HASH_LINE_OID("hash.line_oid", 1),
    HASH_ALGO_LABEL_GOST2015_512("hash.algo_label_gost2015_512", 0),
    HASH_ALGO_LABEL_GOST2015_256("hash.algo_label_gost2015_256", 0),
    HASH_ALGO_LABEL_GOST95("hash.algo_label_gost95", 0),
    HASH_ALGO_LABEL_GOST94("hash.algo_label_gost94", 0),

    
    SIGN_MULTIPLE_OPS("sign.multiple_ops", 0),
    SIGN_FORCE_NOT_APPLICABLE("sign.force_not_applicable", 0),
    SIGN_INDEX_NOT_APPLICABLE("sign.index_not_applicable", 0),
    SIGN_SORT_REQUIRES_FILE("sign.sort_requires_file", 0),
    SIGN_ADD_CHAIN_WITH_POSITIONAL("sign.add_chain_with_positional", 0),
    SIGN_ARCHIVE_WITH_POSITIONAL("sign.archive_with_positional", 0),
    SIGN_ADD_REQUIRES_FILE("sign.add_requires_file", 1),
    SIGN_STRIP_REQUIRES_FILE("sign.strip_requires_file", 1),
    SIGN_INPUT_FILE_REQUIRED("sign.input_file_required", 0),
    SIGN_INVALID_MODE("sign.invalid_mode", 1),
    SIGN_INVALID_ADD("sign.invalid_add", 1),
    SIGN_INVALID_STRIP("sign.invalid_strip", 1),
    SIGN_INDEX_NEGATIVE("sign.index_negative", 1),
    SIGN_INVALID_INDEX("sign.invalid_index", 1),
    SIGN_INVALID_SORT("sign.invalid_sort", 1),

    
    SIGN_DOCUMENT_ONLY_FOR_COSIGN("sign.document_only_for_cosign", 0),
    SIGN_LINE_KEY("sign.line_key", 1),
    SIGN_LINE_MODE("sign.line_mode", 2),
    SIGN_FETCHING_SIGNER_CERT("sign.fetching_signer_cert", 0),
    SIGN_LINE_SIGNER("sign.line_signer", 1),
    SIGN_FULLCHAIN_ISSUER_NOT_FOUND("sign.fullchain_issuer_not_found", 0),
    SIGN_LINE_CHAIN_FULLCHAIN("sign.line_chain_fullchain", 2),
    SIGN_SIGNING("sign.signing", 0),
    SIGN_LINE_SIGNATURE_CREATED("sign.line_signature_created", 1),
    SIGN_AUGMENTING_FIRST("sign.augmenting_first", 0),
    SIGN_LINE_BLT_READY("sign.line_blt_ready", 1),
    SIGN_STRICT_BLT_APPLYING("sign.strict_blt_applying", 0),
    SIGN_LINE_DONE("sign.line_done", 1),
    SIGN_SAVED("sign.saved", 1),
    SIGN_VERIFY_HINT_ATTACHED("sign.verify_hint_attached", 1),
    SIGN_VERIFY_HINT_DETACHED("sign.verify_hint_detached", 2),
    SIGN_VERIFY_HINT_DOCUMENT_SUFFIX("sign.verify_hint_document_suffix", 1),
    SIGN_MODE_WITH_COSIGN("sign.mode_with_cosign", 0),
    SIGN_COSIGN_DETACHED_NEEDS_DOCUMENT("sign.cosign_detached_needs_document", 0),
    SIGN_COSIGN_ATTACHED_NO_DOCUMENT("sign.cosign_attached_no_document", 0),
    SIGN_COSIGN_INTRO("sign.cosign_intro", 0),
    SIGN_LINE_NEW_SIGNER_ADDED("sign.line_new_signer_added", 2),
    SIGN_AUGMENTING_COSIGN("sign.augmenting_cosign", 0),

    
    SIGN_ACTION_ADD_CHAIN("sign.action_add_chain", 0),
    SIGN_SIGNER_CERT_NOT_FOUND("sign.signer_cert_not_found", 1),
    SIGN_CHAIN_ISSUER_NOT_FOUND("sign.chain_issuer_not_found", 1),
    SIGN_CHAIN_ADDED("sign.chain_added", 1),
    SIGN_CHAIN_ALREADY_PRESENT("sign.chain_already_present", 0),
    SIGN_ACTION_ADD_ARCHIVE("sign.action_add_archive", 0),

    
    SIGN_UNREACHABLE("sign.unreachable", 1),
    SIGN_ACTION_ADD_ATTR("sign.action_add_attr", 1),
    SIGN_ACTION_STRIP_TSP("sign.action_strip_tsp", 0),
    SIGN_ACTION_STRIP_OCSP("sign.action_strip_ocsp", 0),
    SIGN_ACTION_STRIP_ARCHIVE("sign.action_strip_archive", 0),
    SIGN_ACTION_STRIP_ARCHIVE_ALL("sign.action_strip_archive_all", 0),
    SIGN_ACTION_STRIP_UNSIGNED("sign.action_strip_unsigned", 0),
    SIGN_STRIP_SIGNATURE_REQUIRES_INDEX("sign.strip_signature_requires_index", 0),
    SIGN_ACTION_STRIP_SIGNATURE("sign.action_strip_signature", 1),

    
    SIGN_ACTION_SORT("sign.action_sort", 1),
    SIGN_NO_CHANGES("sign.no_changes", 0),

    
    SIGN_KEY_FILE_NOT_FOUND("sign.key_file_not_found", 1),
    SIGN_KEYS_DIR_MISSING("sign.keys_dir_missing", 1),
    SIGN_KEYS_DIR_READ_FAILED("sign.keys_dir_read_failed", 2),
    SIGN_NO_P12_FOUND("sign.no_p12_found", 1),
    SIGN_MULTIPLE_P12_FOUND("sign.multiple_p12_found", 2),
    SIGN_NO_INTERACTIVE_CONSOLE("sign.no_interactive_console", 0),
    SIGN_PASSWORD_PROMPT("sign.password_prompt", 0),
    SIGN_PASSWORD_INPUT_CANCELLED("sign.password_input_cancelled", 0),

    
    SIGN_CADES_INDEX_OUT_OF_RANGE("sign_cades.index_out_of_range", 2),
    SIGN_CADES_TST_SERIALIZE_FAILED("sign_cades.tst_serialize_failed", 1),

    
    ATTR_OPS_SIGNER_CERT_NOT_FOUND("attr_ops.signer_cert_not_found", 1),
    ATTR_OPS_TSP_BLOCKS_ATOMIC("attr_ops.tsp_blocks_atomic", 1),
    ATTR_OPS_OCSP_BLOCKS_ATOMIC("attr_ops.ocsp_blocks_atomic", 1),
    ATTR_OPS_TSP_ALREADY_PRESENT("attr_ops.tsp_already_present", 1),
    ATTR_OPS_OCSP_ALREADY_PRESENT("attr_ops.ocsp_already_present", 1),
    ATTR_OPS_TSP_ADDED("attr_ops.tsp_added", 1),
    ATTR_OPS_TSP_REPLACED("attr_ops.tsp_replaced", 1),
    ATTR_OPS_OCSP_ADDED("attr_ops.ocsp_added", 1),
    ATTR_OPS_OCSP_REPLACED("attr_ops.ocsp_replaced", 1),
    ATTR_OPS_TSP_ABSENT("attr_ops.tsp_absent", 1),
    ATTR_OPS_OCSP_ABSENT("attr_ops.ocsp_absent", 1),
    ATTR_OPS_TSP_REMOVED("attr_ops.tsp_removed", 1),
    ATTR_OPS_OCSP_REMOVED("attr_ops.ocsp_removed", 1),
    ATTR_OPS_UNSIGNED_ABSENT("attr_ops.unsigned_absent", 1),
    ATTR_OPS_UNSIGNED_STRIPPED("attr_ops.unsigned_stripped", 1),
    ATTR_OPS_ARCHIVE_GUARD("attr_ops.archive_guard", 2),

    
    ARCHIVE_STAMP_UNKNOWN_DIGEST_ALGO("archive_stamp.unknown_digest_algo", 2),
    ARCHIVE_STAMP_TSA_REQUEST_FAILED("archive_stamp.tsa_request_failed", 2),
    ARCHIVE_STAMP_ADDED("archive_stamp.added", 3),
    ARCHIVE_STAMP_PROVIDER_PREPARE_FAILED("archive_stamp.provider_prepare_failed", 1),
    ARCHIVE_STAMP_VERIFICATION_FAILED("archive_stamp.verification_failed", 1),
    ARCHIVE_STAMP_SIGNATURES_INVALID("archive_stamp.signatures_invalid", 1),
    ARCHIVE_STAMP_SIGNERS_NOT_READY("archive_stamp.signers_not_ready", 1),
    ARCHIVE_STAMP_MESSAGE_DIGEST_ATTR_MISSING("archive_stamp.message_digest_attr_missing", 0),
    ARCHIVE_STAMP_HASH_COMPUTE_FAILED("archive_stamp.hash_compute_failed", 1),
    ARCHIVE_STAMP_ASN1_PARSE_FAILED("archive_stamp.asn1_parse_failed", 1),
    ARCHIVE_STAMP_NONE_TO_STRIP("archive_stamp.none_to_strip", 1),
    ARCHIVE_STAMP_STRIPPED_ALL("archive_stamp.stripped_all", 2),
    ARCHIVE_STAMP_STRIPPED_LAST("archive_stamp.stripped_last", 3),

    
    STRICT_BLT_SIGNER_CERT_NOT_FOUND("strict_blt.signer_cert_not_found", 0),
    STRICT_BLT_NO_EMBEDDED_OCSP("strict_blt.no_embedded_ocsp", 0),
    STRICT_BLT_OCSP_NO_RESPONDER_CERT("strict_blt.ocsp_no_responder_cert", 0),
    STRICT_BLT_RESPONDER_CERT_READ_FAILED("strict_blt.responder_cert_read_failed", 1),
    STRICT_BLT_NO_TSP("strict_blt.no_tsp", 0),
    STRICT_BLT_TSA_CERT_NOT_FOUND("strict_blt.tsa_cert_not_found", 0),
    STRICT_BLT_TSA_ISSUER_NOT_FOUND("strict_blt.tsa_issuer_not_found", 1),
    STRICT_BLT_LINE_OCSP_REQUEST("strict_blt.line_ocsp_request", 2),
    STRICT_BLT_OCSP_REQUEST_FAILED("strict_blt.ocsp_request_failed", 1),
    STRICT_BLT_TST_REBUILD_FAILED("strict_blt.tst_rebuild_failed", 1),
    STRICT_BLT_LINE_REVOCATION_ADDED("strict_blt.line_revocation_added", 0),
    STRICT_BLT_LINE_CHAINS_ADDED("strict_blt.line_chains_added", 0),
    STRICT_BLT_TSP_PARSE_FAILED("strict_blt.tsp_parse_failed", 1),
    STRICT_BLT_TST_CERTS_READ_FAILED("strict_blt.tst_certs_read_failed", 1),
    STRICT_BLT_TST_PARSE_FAILED("strict_blt.tst_parse_failed", 1),

    
    SIGNER_SELECTOR_MULTIPLE_SIGNERS_NEED_INDEX("signer_selector.multiple_signers_need_index", 1),
    SIGNER_SELECTOR_INDEX_OUT_OF_RANGE("signer_selector.index_out_of_range", 3),

    
    CERTIFICATES_OPS_ARCHIVE_GUARD("certificates_ops.archive_guard", 1),
    CERTIFICATES_OPS_CERT_ENCODE_FAILED("certificates_ops.cert_encode_failed", 1),
    CERTIFICATES_OPS_CERT_PARSE_FAILED("certificates_ops.cert_parse_failed", 1),

    
    CADES_BLT_ISSUER_NOT_FOUND("cades_blt.issuer_not_found", 1),
    CADES_BLT_SIGNER_CERT_NOT_FOUND("cades_blt.signer_cert_not_found", 0),
    CADES_BLT_LINE_TSA_REQUEST("cades_blt.line_tsa_request", 1),
    CADES_BLT_LINE_OCSP_REQUEST("cades_blt.line_ocsp_request", 2),

    
    SORT_SIGNER_INFOS_NOTHING_TO_SORT("sort_signer_infos.nothing_to_sort", 1),
    SORT_SIGNER_INFOS_MISMATCH("sort_signer_infos.mismatch", 2),
    SORT_SIGNER_INFOS_LINE_GEN_TIME("sort_signer_infos.line_gen_time", 2),
    SORT_SIGNER_INFOS_NO_TSA_MARK("sort_signer_infos.no_tsa_mark", 0),
    SORT_SIGNER_INFOS_ALREADY_SORTED("sort_signer_infos.already_sorted", 1),
    SORT_SIGNER_INFOS_NEW_ORDER("sort_signer_infos.new_order", 2),
    SORT_SIGNER_INFOS_CRITERION_TIME("sort_signer_infos.criterion_time", 0),
    SORT_SIGNER_INFOS_CRITERION_DER("sort_signer_infos.criterion_der", 0),

    
    STRIP_SIGNATURE_ONLY_ONE("strip_signature.only_one", 0),
    STRIP_SIGNATURE_REMOVED("strip_signature.removed", 2),

    
    CO_SIGN_UNSUPPORTED_CONTENT_TYPE("co_sign.unsupported_content_type", 2),
    CO_SIGN_DETACHED_NEEDS_DOCUMENT("co_sign.detached_needs_document", 0),
    CO_SIGN_ARCHIVE_GUARD("co_sign.archive_guard", 1),

    
    KZ_EKU_ROLE_INDIVIDUAL("kz_eku_role.individual", 0),
    KZ_EKU_ROLE_INDIVIDUAL_INFO_SYSTEM("kz_eku_role.individual_info_system", 0),
    KZ_EKU_ROLE_LEGAL_ENTITY("kz_eku_role.legal_entity", 0),
    KZ_EKU_ROLE_CHIEF_EXECUTIVE("kz_eku_role.chief_executive", 0),
    KZ_EKU_ROLE_SIGNER("kz_eku_role.signer", 0),
    KZ_EKU_ROLE_FINANCIAL_SIGNER("kz_eku_role.financial_signer", 0),
    KZ_EKU_ROLE_HR_EMPLOYEE("kz_eku_role.hr_employee", 0),
    KZ_EKU_ROLE_ORG_EMPLOYEE("kz_eku_role.org_employee", 0),
    KZ_EKU_ROLE_LEGAL_ENTITY_INFO_SYSTEM("kz_eku_role.legal_entity_info_system", 0),
    KZ_EKU_ROLE_PRESIDENTIAL_ARCHIVE_EMPLOYEE("kz_eku_role.presidential_archive_employee", 0),
    KZ_EKU_ROLE_CENTRAL_ARCHIVE_EMPLOYEE("kz_eku_role.central_archive_employee", 0),
    KZ_EKU_ROLE_DEPARTMENTAL_ARCHIVE_EMPLOYEE("kz_eku_role.departmental_archive_employee", 0),
    KZ_EKU_ROLE_CIVIL_SERVANT("kz_eku_role.civil_servant", 0),

    
    RUNNER_KALKAN_C_UNAVAILABLE("runner.kalkan_c_unavailable", 0),
    RUNNER_UNKNOWN_CA_PROVIDER("runner.unknown_ca_provider", 1),

    
    VERIFY_LIBRARY_JARS_CONFIRMED("verify_library_jars.confirmed", 1),

    
    VERIFICATION_PROVIDER_DETACHED_UNSUPPORTED("verification_provider.detached_unsupported", 1),

    
    MESSAGES_ARG_COUNT_MISMATCH("messages.arg_count_mismatch", 3),
    MESSAGES_RESOURCE_NOT_FOUND("messages.resource_not_found", 1),
    JSON_WRITER_UNSUPPORTED_TYPE("json_writer.unsupported_type", 1),
    PARSING_CADES_LEVEL_NOT_BB("parsing.cades_level_not_bb", 1),
    PARSING_CADES_LEVEL_LTA("parsing.cades_level_lta", 0),
    PARSING_CADES_LEVEL_LT("parsing.cades_level_lt", 0),
    PARSING_CADES_LEVEL_T("parsing.cades_level_t", 0),
    PARSING_CADES_LEVEL_BB("parsing.cades_level_bb", 0),
    SIGNER_SELECTOR_SINGLE_LABEL("signer_selector.single_label", 0),
    SIGNER_SELECTOR_ALL_LABEL("signer_selector.all_label", 0);

    private final String key;
    private final int argCount;

    MsgKey(String key, int argCount) {
        this.key = key;
        this.argCount = argCount;
    }

    
    public String key() {
        return key;
    }

    
    public int argCount() {
        return argCount;
    }
}
