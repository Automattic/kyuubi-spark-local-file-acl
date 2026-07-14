package com.automattic.kyuubi.spark.localfileacl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.kyuubi.KyuubiException;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LogEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The audit stream operators pull: exactly one record per decision, on a fixed, safe schema. */
class AuditLogSpec {

  private static final Pattern FIELD =
      Pattern.compile("(\\w+)=(?:\"((?:[^\"\\\\]|\\\\.)*)\"|(\\S+))");

  @TempDir Path tempDir;

  private AuditCapture audit;
  private Path root;
  private Path uploadRoot;
  private Path aclFile;
  private Path aliceFile;
  private Path sharedFile;
  private Path secretFile;
  private MutableClock clock;

  @BeforeEach
  void setUp() throws Exception {
    root = TestSupport.real(tempDir);
    uploadRoot = Files.createDirectories(root.resolve("upload"));
    aclFile = root.resolve("acl.yaml");
    aliceFile =
        Files.writeString(Files.createDirectories(root.resolve("alice")).resolve("app.conf"), "x");
    sharedFile =
        Files.writeString(Files.createDirectories(root.resolve("shared")).resolve("lib.jar"), "x");
    secretFile = Files.writeString(root.resolve("secret.keytab"), "x");
    clock = new MutableClock();
    TestSupport.writeAcl(
        aclFile,
        """
        version: 1
        users:
          alice:
            allow:
              - '%s/alice/*.conf'
        groups:
          data-eng:
            allow:
              - '%s/shared/*.jar'
        """
            .formatted(root, root));
    audit = new AuditCapture();
  }

  @AfterEach
  void tearDown() {
    audit.close();
  }

  private LocalFileAclEngine engine(GroupResolver resolver) {
    return TestSupport.newEngine(aclFile, uploadRoot, resolver, clock);
  }

  private static GroupResolver groups(String... names) {
    return user -> Set.of(names);
  }

  /** Parses one logfmt record into its fields, the way an operator's log pipeline would. */
  private static Map<String, String> fields(String record) {
    assertTrue(record.startsWith("event=local_file_acl decision="), record);
    Map<String, String> parsed = new LinkedHashMap<>();
    Matcher matcher = FIELD.matcher(record);
    while (matcher.find()) {
      parsed.put(matcher.group(1), matcher.group(2) != null ? matcher.group(2) : matcher.group(3));
    }
    return parsed;
  }

  private Map<String, String> onlyRecord(Level expectedLevel) {
    LogEvent event = audit.onlyEvent();
    assertEquals(expectedLevel, event.getLevel());
    return fields(event.getMessage().getFormattedMessage());
  }

  private static Map<String, String> recordAt(AuditCapture audit, int index, Level expectedLevel) {
    LogEvent event = audit.events().get(index);
    assertEquals(expectedLevel, event.getLevel());
    return fields(event.getMessage().getFormattedMessage());
  }

  @Test
  void recordsUserRuleGrantWithoutResolvingGroups() {
    GroupResolver exploding =
        user -> {
          throw new AssertionError("a username match must not force group resolution");
        };
    engine(exploding).validate("alice", Map.of("spark.files", aliceFile.toString()));

    Map<String, String> record = onlyRecord(Level.INFO);
    assertEquals("ALLOW", record.get("decision"));
    assertEquals("alice", record.get("user"));
    assertEquals("spark.files", record.get("key"));
    assertEquals(aliceFile.toString(), record.get("resource"));
    assertEquals("user-rule", record.get("reason"));
    assertEquals("user", record.get("principal_type"));
    assertEquals("alice", record.get("principal"));
    assertEquals(root + "/alice/*.conf", record.get("pattern"));
  }

  @Test
  void recordsGroupRuleGrantWithTheMatchingGroup() {
    engine(groups("data-eng")).validate("bob", Map.of("spark.jars", sharedFile.toString()));

    Map<String, String> record = onlyRecord(Level.INFO);
    assertEquals("ALLOW", record.get("decision"));
    assertEquals("bob", record.get("user"));
    assertEquals("spark.jars", record.get("key"));
    assertEquals("group-rule", record.get("reason"));
    assertEquals("group", record.get("principal_type"));
    assertEquals("data-eng", record.get("principal"));
  }

  @Test
  void recordsUploadExemptionGrantAndCrossBatchDeny() throws Exception {
    String batchId = UUID.randomUUID().toString();
    Path staged = TestSupport.stageUpload(uploadRoot, batchId, "job.jar");
    engine(groups()).validate("alice", TestSupport.uploadedConf(batchId, staged.toString()));

    Map<String, String> allow = onlyRecord(Level.INFO);
    assertEquals("ALLOW", allow.get("decision"));
    assertEquals("upload-exemption", allow.get("reason"));
    assertEquals("upload", allow.get("principal_type"));
    assertEquals(staged.toString(), allow.get("resource"));

    Path otherBatch =
        TestSupport.stageUpload(uploadRoot, UUID.randomUUID().toString(), "other.jar");
    assertThrows(
        KyuubiException.class,
        () ->
            engine(groups())
                .validate("alice", TestSupport.uploadedConf(batchId, otherBatch.toString())));

    Map<String, String> deny = recordAt(audit, 1, Level.WARN);
    assertEquals("DENY", deny.get("decision"));
    assertEquals("cross-batch-upload", deny.get("reason"));
    assertEquals(otherBatch.toString(), deny.get("resource"));
  }

  @Test
  void recordsDenyWhenNoRuleMatches() {
    assertThrows(
        KyuubiException.class,
        () ->
            engine(groups("staff"))
                .validate("mallory", Map.of("spark.files", secretFile.toString())));

    Map<String, String> record = onlyRecord(Level.WARN);
    assertEquals("DENY", record.get("decision"));
    assertEquals("mallory", record.get("user"));
    assertEquals("no-matching-rule", record.get("reason"));
    assertEquals(secretFile.toString(), record.get("resource"));
    assertEquals("", record.get("principal_type"));
    assertEquals("", record.get("principal"));
    assertEquals("", record.get("pattern"));
  }

  @Test
  void recordsDenyWhenGroupResolutionFails() {
    GroupResolver failing =
        user -> {
          throw new IllegalStateException("LDAP down");
        };
    assertThrows(
        KyuubiException.class,
        () -> engine(failing).validate("bob", Map.of("spark.files", sharedFile.toString())));

    Map<String, String> record = onlyRecord(Level.WARN);
    assertEquals("group-resolution-failed", record.get("reason"));
    assertEquals("bob", record.get("user"));
  }

  @Test
  void recordsDenyWhenTheAclStateIsInvalid() throws Exception {
    PolicyStore store =
        TestSupport.newLoadedStore(aclFile, uploadRoot, Duration.ofSeconds(60), clock);
    LocalFileAclEngine engine =
        new LocalFileAclEngine(PolicedKeys.fromSettings(null, null), store, groups(), uploadRoot);
    TestSupport.writeAcl(aclFile, "not: [valid");
    clock.advance(Duration.ofSeconds(61));

    assertThrows(
        KyuubiException.class,
        () -> engine.validate("alice", Map.of("spark.files", aliceFile.toString())));

    Map<String, String> record = onlyRecord(Level.WARN);
    assertEquals("invalid-acl-state", record.get("reason"));
    assertEquals("alice", record.get("user"));
  }

  @Test
  void recordsDenyForAMalformedSubmittedResource() {
    assertThrows(
        KyuubiException.class,
        () -> engine(groups()).validate("alice", Map.of("spark.files", root + "/alice/*.conf")));

    Map<String, String> record = onlyRecord(Level.WARN);
    assertEquals("invalid-resource", record.get("reason"));
    assertEquals(root + "/alice/*.conf", record.get("resource"));
  }

  @Test
  void emitsNothingForRemoteAndUnpolicedResources() {
    engine(groups())
        .validate(
            "alice",
            Map.of(
                "spark.files", "hdfs://nn/x.jar,s3a://bucket/y.jar",
                "spark.executor.memory", "4g"));
    assertTrue(audit.events().isEmpty(), audit.messages().toString());
  }

  @Test
  void recordsEveryEvaluatedResourceAndClaimsNothingAfterTheFirstDeny() throws Exception {
    Path trailing = Files.writeString(root.resolve("alice").resolve("extra.conf"), "x");
    assertThrows(
        KyuubiException.class,
        () ->
            engine(groups())
                .validate(
                    "alice", Map.of("spark.files", aliceFile + "," + secretFile + "," + trailing)));

    // The authorized entry ahead of the denial is audited; validation stops at the denial, so the
    // trailing entry — never evaluated — gets no fabricated decision.
    List<LogEvent> events = audit.events();
    assertEquals(2, events.size(), audit.messages().toString());
    assertEquals("ALLOW", recordAt(audit, 0, Level.INFO).get("decision"));
    Map<String, String> deny = recordAt(audit, 1, Level.WARN);
    assertEquals("DENY", deny.get("decision"));
    assertEquals(secretFile.toString(), deny.get("resource"));
  }

  @Test
  void escapesCraftedValuesOntoASingleRecord() {
    // Quote, newline, control character, and backslash in a username: none of them may close the
    // field, forge a second record, or split the decision across lines.
    String bel = String.valueOf((char) 0x07);
    String user = "ev\"il\nuser" + bel + "\\x";
    assertThrows(
        KyuubiException.class,
        () -> engine(groups()).validate(user, Map.of("spark.files", secretFile.toString())));

    String record = audit.onlyMessage();
    assertFalse(record.contains("\n"), record);
    assertFalse(record.contains("\r"), record);
    assertFalse(record.contains(bel), record);
    assertTrue(record.contains("user=\"ev\\\"il\\nuser" + "\\" + "u0007\\\\x\""), record);
    // It still parses as exactly one record, with the crafted name preserved but inert.
    assertEquals("DENY", fields(record).get("decision"));
    assertEquals(secretFile.toString(), fields(record).get("resource"));
  }

  @Test
  void escapesUnicodeLineBreaksThatOnlyUnicodeAwareReadersSplitOn() {
    // U+0085 NEXT LINE, U+2028 LINE SEPARATOR, U+2029 PARAGRAPH SEPARATOR: not C0 controls, but
    // line terminators to a Unicode-aware log processor, which would otherwise read this single
    // decision as several records.
    String nextLine = String.valueOf((char) 0x85);
    String lineSeparator = String.valueOf((char) 0x2028);
    String paragraphSeparator = String.valueOf((char) 0x2029);
    String user = "a" + nextLine + "b" + lineSeparator + "c" + paragraphSeparator + "d";
    assertThrows(
        KyuubiException.class,
        () -> engine(groups()).validate(user, Map.of("spark.files", secretFile.toString())));

    String record = audit.onlyMessage();
    assertFalse(record.contains(nextLine), record);
    assertFalse(record.contains(lineSeparator), record);
    assertFalse(record.contains(paragraphSeparator), record);
    assertEquals(1, record.lines().count(), record);
    assertTrue(
        record.contains("user=\"a" + "\\" + "u0085b" + "\\" + "u2028c" + "\\" + "u2029d\""),
        record);
  }
}
