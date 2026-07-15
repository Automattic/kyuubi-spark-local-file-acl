package com.automattic.kyuubi.spark.localfileacl;

import java.util.Locale;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Emits one single-line record per local-file authorization decision on a dedicated SLF4J category,
 * so operators can route the decision stream to its own file (Log4j2 logger {@value #LOGGER_NAME},
 * additivity off) and pull it for auditing. Grants log at INFO, denials at WARN.
 *
 * <p>The schema is fixed: fields that do not apply to a decision are still present, with an empty
 * value. Every value is escaped, so a crafted username, path, or configuration value cannot forge a
 * record or split one across lines.
 */
final class AuditLog {

  static final String LOGGER_NAME = "com.automattic.kyuubi.spark.localfileacl.audit";

  private static final Logger AUDIT = LoggerFactory.getLogger(LOGGER_NAME);

  /** U+2028 LINE SEPARATOR. */
  private static final char LINE_SEPARATOR = (char) 0x2028;

  /** U+2029 PARAGRAPH SEPARATOR. */
  private static final char PARAGRAPH_SEPARATOR = (char) 0x2029;

  private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

  private AuditLog() {}

  /** A grant: {@code principalType} is the kind of rule that matched (user, group, or upload). */
  static void allow(
      String user,
      String key,
      String resource,
      String reason,
      String principalType,
      String principal,
      String pattern) {
    AUDIT.info(record("ALLOW", user, key, resource, reason, principalType, principal, pattern));
  }

  /** A denial: no rule matched, so the principal and pattern fields stay empty. */
  static void deny(String user, String key, String resource, String reason) {
    AUDIT.warn(record("DENY", user, key, resource, reason, "", "", ""));
  }

  /** The kind of reload transition; each carries the level its event logs at. */
  enum ReloadOutcome {
    LOADED, // initial load succeeded
    CHANGED, // a running policy was replaced
    RECOVERED, // a valid policy replaced an invalid one
    INVALIDATED, // a running policy became invalid — logs at WARN
    LOAD_FAILED; // the initial load itself failed; no policy was ever active

    /** Whether this outcome is a failure and should log at WARN rather than INFO. */
    boolean isFailure() {
      return this == INVALIDATED || this == LOAD_FAILED;
    }

    String wire() {
      return name().toLowerCase(Locale.ROOT);
    }
  }

  /**
   * A policy lifecycle event on reload: one record per state transition. {@code policy} is the
   * newly published policy (null when a reload produced an invalid state); its counts describe the
   * active policy. A same-digest {@code changed} event whose {@code unresolved} count dropped marks
   * an omitted missing-file rule becoming active. Which exact rules changed is not audited here —
   * that belongs in the configuration's own version-control trail.
   */
  static void reload(
      ReloadOutcome outcome,
      String source,
      String oldDigest,
      String newDigest,
      AclPolicy policy,
      String error) {
    StringBuilder summary = new StringBuilder(200);
    summary.append("event=local_file_acl_reload");
    append(summary, "outcome", outcome.wire());
    append(summary, "source", source);
    append(summary, "old_digest", oldDigest);
    append(summary, "new_digest", newDigest);
    appendInt(summary, "users", policy == null ? 0 : policy.userRules().size());
    appendInt(summary, "groups", policy == null ? 0 : policy.groupRules().size());
    appendInt(summary, "rules", policy == null ? 0 : policy.ruleCount());
    appendInt(summary, "unresolved", policy == null ? 0 : policy.unresolvedPaths().size());
    append(summary, "error", error);
    if (outcome.isFailure()) {
      AUDIT.warn(summary.toString());
    } else {
      AUDIT.info(summary.toString());
    }
  }

  private static String record(
      String decision,
      String user,
      String key,
      String resource,
      String reason,
      String principalType,
      String principal,
      String pattern) {
    StringBuilder line = new StringBuilder(160);
    line.append("event=local_file_acl decision=").append(decision);
    append(line, "user", user);
    append(line, "key", key);
    append(line, "resource", resource);
    append(line, "reason", reason);
    append(line, "principal_type", principalType);
    append(line, "principal", principal);
    append(line, "pattern", pattern);
    return line.toString();
  }

  private static void appendInt(StringBuilder line, String field, int value) {
    line.append(' ').append(field).append('=').append(value);
  }

  private static void append(StringBuilder line, String field, String value) {
    line.append(' ').append(field).append("=\"");
    escape(line, value == null ? "" : value);
    line.append('"');
  }

  /**
   * Escapes every character a log processor could read as a record or field boundary. That means
   * all ISO control characters — C0, DEL, and the C1 range, which includes U+0085 NEXT LINE — plus
   * the two Unicode separators, all of which Unicode-aware readers treat as line breaks.
   */
  private static void escape(StringBuilder line, String value) {
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
        case '\\' -> line.append("\\\\");
        case '"' -> line.append("\\\"");
        case '\n' -> line.append("\\n");
        case '\r' -> line.append("\\r");
        case '\t' -> line.append("\\t");
        default -> {
          if (Character.isISOControl(c) || c == LINE_SEPARATOR || c == PARAGRAPH_SEPARATOR) {
            appendUnicodeEscape(line, c);
          } else {
            line.append(c);
          }
        }
      }
    }
  }

  private static void appendUnicodeEscape(StringBuilder line, char c) {
    line.append("\\u");
    for (int shift = 12; shift >= 0; shift -= 4) {
      line.append(HEX_DIGITS[(c >> shift) & 0xf]);
    }
  }
}
