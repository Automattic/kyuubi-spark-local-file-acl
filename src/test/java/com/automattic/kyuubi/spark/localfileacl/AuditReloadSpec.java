package com.automattic.kyuubi.spark.localfileacl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LogEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The reload lifecycle stream: a summary event plus one unambiguous record per changed rule. */
class AuditReloadSpec {

  private static final Duration INTERVAL = Duration.ofSeconds(60);
  private static final String SUMMARY_PREFIX = "event=local_file_acl_reload ";
  private static final String CHANGE_PREFIX = "event=local_file_acl_reload_change";

  @TempDir Path tempDir;

  private AuditCapture audit;
  private Path root;
  private Path uploadRoot;
  private Path aclFile;
  private Path fileA;
  private Path fileB;
  private MutableClock clock;

  @BeforeEach
  void setUp() throws Exception {
    root = TestSupport.real(tempDir);
    uploadRoot = Files.createDirectories(root.resolve("upload"));
    aclFile = root.resolve("acl.yaml");
    fileA = Files.writeString(root.resolve("a.conf"), "a");
    fileB = Files.writeString(root.resolve("b.conf"), "b");
    clock = new MutableClock();
    audit = new AuditCapture();
  }

  @AfterEach
  void tearDown() {
    audit.close();
  }

  private String allow(Path... paths) {
    return allowFor("alice", paths);
  }

  private String allowFor(String principal, Path... paths) {
    StringBuilder yaml = new StringBuilder("version: 2\nusers:\n  " + principal + ":\n");
    for (Path path : paths) {
      yaml.append("    - '").append(path).append("'\n");
    }
    return yaml.toString();
  }

  private PolicyStore load(AclYamlLoader.Options options) throws Exception {
    return TestSupport.newLoadedStore(aclFile, options, INTERVAL, clock);
  }

  private AclYamlLoader.Options strict() {
    return new AclYamlLoader.Options(uploadRoot, null, false, true);
  }

  private AclYamlLoader.Options lenient() {
    return new AclYamlLoader.Options(uploadRoot, null, false, false);
  }

  private void tick() {
    clock.advance(INTERVAL.plusSeconds(1));
  }

  private List<LogEvent> summaries() {
    return audit.eventsWithPrefix(SUMMARY_PREFIX);
  }

  private LogEvent lastSummaryEvent() {
    List<LogEvent> events = summaries();
    return events.get(events.size() - 1);
  }

  private Map<String, String> lastSummary() {
    return TestSupport.parseLogfmt(lastSummaryEvent().getMessage().getFormattedMessage());
  }

  private List<Map<String, String>> changeRecords() {
    return audit.eventsWithPrefix(CHANGE_PREFIX).stream()
        .map(e -> TestSupport.parseLogfmt(e.getMessage().getFormattedMessage()))
        .toList();
  }

  private Optional<Map<String, String>> change(String kind, String pattern) {
    return changeRecords().stream()
        .filter(r -> r.get("change").equals(kind) && r.get("pattern").equals(pattern))
        .findFirst();
  }

  @Test
  void initialLoadEmitsALoadedSummaryWithNoChangeRecords() throws Exception {
    TestSupport.writeAcl(aclFile, allow(fileA));
    load(strict());

    assertEquals(1, summaries().size());
    assertEquals(Level.INFO, lastSummaryEvent().getLevel());
    Map<String, String> summary = lastSummary();
    assertEquals("loaded", summary.get("outcome"));
    assertEquals(aclFile.toString(), summary.get("source"));
    assertEquals("1", summary.get("rules"));
    assertEquals("", summary.get("old_digest"));
    assertTrue(changeRecords().isEmpty(), changeRecords().toString());
  }

  @Test
  void aRuntimeChangeCountsAndNamesTheAddedAndRemovedRules() throws Exception {
    TestSupport.writeAcl(aclFile, allow(fileA));
    PolicyStore store = load(strict());

    TestSupport.writeAcl(aclFile, allow(fileB));
    tick();
    store.maybeReload();

    Map<String, String> summary = lastSummary();
    assertEquals("changed", summary.get("outcome"));
    assertEquals("1", summary.get("added"));
    assertEquals("1", summary.get("removed"));
    assertNotEqualsDigests(summary);

    Map<String, String> added = change("added", fileB.toString()).orElseThrow();
    assertEquals("user", added.get("type"));
    assertEquals("alice", added.get("principal"));
    assertTrue(change("removed", fileA.toString()).isPresent(), changeRecords().toString());
  }

  private static void assertNotEqualsDigests(Map<String, String> event) {
    assertFalse(event.get("old_digest").isEmpty());
    assertFalse(event.get("new_digest").isEmpty());
    assertFalse(event.get("old_digest").equals(event.get("new_digest")));
  }

  @Test
  void aMissingFileBecomingAvailableIsNamedAsResolved() throws Exception {
    Path later = root.resolve("later.conf");
    TestSupport.writeAcl(aclFile, allow(fileA, later));
    PolicyStore store = load(lenient());

    Map<String, String> loaded = lastSummary();
    assertEquals("loaded", loaded.get("outcome"));
    assertEquals("1", loaded.get("unresolved"));

    // The file appears; the YAML is not touched, so the digest is unchanged.
    Files.writeString(later, "x");
    tick();
    store.maybeReload();

    Map<String, String> summary = lastSummary();
    assertEquals("changed", summary.get("outcome"));
    assertEquals("0", summary.get("unresolved"));
    assertEquals("1", summary.get("resolved"));
    // The rule identity was already present (as omitted) before, so this is resolved, not added.
    assertEquals("0", summary.get("added"));
    assertEquals(summary.get("old_digest"), summary.get("new_digest"));

    Map<String, String> resolved = change("resolved", later.toString()).orElseThrow();
    assertEquals("user", resolved.get("type"));
    assertEquals("alice", resolved.get("principal"));
  }

  @Test
  void aMissingRuleMovingBetweenPrincipalsStaysVisible() throws Exception {
    // P2a: while the file is absent, no rule is active for anyone, but reassigning the omitted
    // rule from one principal to another must still show up in the diff.
    Path missing = root.resolve("missing.conf");
    TestSupport.writeAcl(aclFile, allowFor("alice", missing));
    PolicyStore store = load(lenient());

    TestSupport.writeAcl(aclFile, allowFor("analysts", missing));
    tick();
    store.maybeReload();

    Map<String, String> summary = lastSummary();
    assertEquals("changed", summary.get("outcome"));
    assertEquals("1", summary.get("added"));
    assertEquals("1", summary.get("removed"));

    Map<String, String> added = change("added", missing.toString()).orElseThrow();
    assertEquals("analysts", added.get("principal"));
    Map<String, String> removed = change("removed", missing.toString()).orElseThrow();
    assertEquals("alice", removed.get("principal"));
  }

  @Test
  void aCommaInAPathStaysInOneField() throws Exception {
    // P2c: commas are legal in paths; a detail record keeps the whole path in one escaped field
    // rather than joining values with an ambiguous comma.
    Path comma = Files.writeString(root.resolve("a,b.conf"), "x");
    TestSupport.writeAcl(aclFile, allow(fileA));
    PolicyStore store = load(strict());

    TestSupport.writeAcl(aclFile, allow(fileA, comma));
    tick();
    store.maybeReload();

    assertEquals("1", lastSummary().get("added"));
    Map<String, String> added = change("added", comma.toString()).orElseThrow();
    // The comma-bearing path is recovered intact, not split into two entries.
    assertEquals(comma.toString(), added.get("pattern"));
  }

  @Test
  void invalidationEmitsOneWarnThenStaysQuietWhileInvalid() throws Exception {
    TestSupport.writeAcl(aclFile, allow(fileA));
    PolicyStore store = load(strict());
    int afterLoad = summaries().size();

    TestSupport.writeAcl(aclFile, "not: [valid");
    tick();
    store.maybeReload();

    assertEquals(afterLoad + 1, summaries().size());
    assertEquals(Level.WARN, lastSummaryEvent().getLevel());
    Map<String, String> summary = lastSummary();
    assertEquals("invalidated", summary.get("outcome"));
    assertFalse(summary.get("error").isEmpty());

    int afterInvalidation = summaries().size();
    tick();
    store.maybeReload();
    assertEquals(afterInvalidation, summaries().size());
  }

  @Test
  void aFailedInitialLoadIsClassifiedAsLoadFailedNotInvalidated() throws Exception {
    // P2b: at startup no policy was ever active, so the failure is distinct from a running policy
    // being revoked.
    TestSupport.writeAcl(aclFile, "not: [valid");
    assertThrows(IllegalStateException.class, () -> load(strict()));

    Map<String, String> summary = lastSummary();
    assertEquals("load_failed", summary.get("outcome"));
    assertEquals(Level.WARN, lastSummaryEvent().getLevel());
    assertEquals("", summary.get("old_digest"));
    assertFalse(summary.get("error").isEmpty());
  }

  @Test
  void recoveryFromInvalidEmitsARecoveredEvent() throws Exception {
    TestSupport.writeAcl(aclFile, allow(fileA));
    PolicyStore store = load(strict());
    TestSupport.writeAcl(aclFile, "not: [valid");
    tick();
    store.maybeReload();

    TestSupport.writeAcl(aclFile, allow(fileA, fileB));
    tick();
    store.maybeReload();

    Map<String, String> summary = lastSummary();
    assertEquals("recovered", summary.get("outcome"));
    assertEquals(Level.INFO, lastSummaryEvent().getLevel());
    assertEquals("2", summary.get("rules"));
  }

  @Test
  void anUnchangedReloadEmitsNoEvent() throws Exception {
    TestSupport.writeAcl(aclFile, allow(fileA));
    PolicyStore store = load(strict());
    int afterLoad = summaries().size();

    tick();
    store.maybeReload();

    assertEquals(afterLoad, summaries().size());
  }

  @Test
  void anAuditFailureDoesNotInvalidateThePublishedPolicy() throws Exception {
    // P1: a fault in diff construction or the logging backend during reload audit emission must not
    // undo the already-published policy.
    TestSupport.writeAcl(aclFile, allow(fileA));
    audit.close(); // replace the capturing appender with one that fails on every emit
    try (ThrowingAuditAppender ignored = ThrowingAuditAppender.install()) {
      PolicyStore store = load(strict());
      // The load audit threw, but the policy is still published.
      assertInstanceOf(AclState.Valid.class, store.current());

      TestSupport.writeAcl(aclFile, allow(fileB));
      tick();
      store.maybeReload();

      // The changed-event audit threw too, yet the new policy took effect.
      AclState.Valid valid = assertInstanceOf(AclState.Valid.class, store.current());
      assertTrue(valid.policy().rulesForUser("alice").get(0).matches(fileB));
    }
  }
}
