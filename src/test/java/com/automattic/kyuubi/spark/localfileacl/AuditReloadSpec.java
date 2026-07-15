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
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LogEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The reload lifecycle stream: one summary record per state transition. */
class AuditReloadSpec {

  private static final Duration INTERVAL = Duration.ofSeconds(60);
  private static final String RELOAD_PREFIX = "event=local_file_acl_reload";

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
    return TestSupport.usersAcl(Map.of("alice", List.of(paths)));
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

  private List<LogEvent> reloadEvents() {
    return audit.eventsWithPrefix(RELOAD_PREFIX);
  }

  private LogEvent lastReloadEvent() {
    List<LogEvent> events = reloadEvents();
    return events.get(events.size() - 1);
  }

  private Map<String, String> lastReload() {
    return TestSupport.parseLogfmt(lastReloadEvent().getMessage().getFormattedMessage());
  }

  @Test
  void initialLoadEmitsALoadedSummaryAtInfo() throws Exception {
    TestSupport.writeAcl(aclFile, allow(fileA));
    load(strict());

    assertEquals(1, reloadEvents().size());
    assertEquals(Level.INFO, lastReloadEvent().getLevel());
    Map<String, String> event = lastReload();
    assertEquals("loaded", event.get("outcome"));
    assertEquals(aclFile.toString(), event.get("source"));
    assertEquals("1", event.get("rules"));
    assertEquals("", event.get("old_digest"));
  }

  @Test
  void aRuntimeChangeCarriesTheDigestTransition() throws Exception {
    TestSupport.writeAcl(aclFile, allow(fileA));
    PolicyStore store = load(strict());

    TestSupport.writeAcl(aclFile, allow(fileB));
    tick();
    store.maybeReload();

    Map<String, String> event = lastReload();
    assertEquals("changed", event.get("outcome"));
    assertFalse(event.get("old_digest").isEmpty());
    assertFalse(event.get("new_digest").isEmpty());
    assertFalse(event.get("old_digest").equals(event.get("new_digest")));
  }

  @Test
  void aMissingFileActivatingShowsAsChangedWithALowerUnresolvedCount() throws Exception {
    // The reload feature no longer names which rule; a same-digest changed event whose unresolved
    // count fell is what marks a missing file becoming available.
    Path later = root.resolve("later.conf");
    TestSupport.writeAcl(aclFile, allow(fileA, later));
    PolicyStore store = load(lenient());

    Map<String, String> loaded = lastReload();
    assertEquals("loaded", loaded.get("outcome"));
    assertEquals("1", loaded.get("unresolved"));

    Files.writeString(later, "x");
    tick();
    store.maybeReload();

    Map<String, String> event = lastReload();
    assertEquals("changed", event.get("outcome"));
    assertEquals("0", event.get("unresolved"));
    // Activation came from the forced reparse, not a content edit, so the digest did not move.
    assertEquals(event.get("old_digest"), event.get("new_digest"));
  }

  @Test
  void invalidationEmitsOneWarnThenStaysQuietWhileInvalid() throws Exception {
    TestSupport.writeAcl(aclFile, allow(fileA));
    PolicyStore store = load(strict());
    int afterLoad = reloadEvents().size();

    TestSupport.writeAcl(aclFile, "not: [valid");
    tick();
    store.maybeReload();

    assertEquals(afterLoad + 1, reloadEvents().size());
    assertEquals(Level.WARN, lastReloadEvent().getLevel());
    Map<String, String> event = lastReload();
    assertEquals("invalidated", event.get("outcome"));
    assertFalse(event.get("error").isEmpty());

    int afterInvalidation = reloadEvents().size();
    tick();
    store.maybeReload();
    assertEquals(afterInvalidation, reloadEvents().size());
  }

  @Test
  void aFailedInitialLoadIsClassifiedAsLoadFailed() throws Exception {
    TestSupport.writeAcl(aclFile, "not: [valid");
    assertThrows(IllegalStateException.class, () -> load(strict()));

    Map<String, String> event = lastReload();
    assertEquals("load_failed", event.get("outcome"));
    assertEquals(Level.WARN, lastReloadEvent().getLevel());
    assertEquals("", event.get("old_digest"));
    assertFalse(event.get("error").isEmpty());
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

    Map<String, String> event = lastReload();
    assertEquals("recovered", event.get("outcome"));
    assertEquals(Level.INFO, lastReloadEvent().getLevel());
    assertEquals("2", event.get("rules"));
  }

  @Test
  void anUnchangedReloadEmitsNoEvent() throws Exception {
    TestSupport.writeAcl(aclFile, allow(fileA));
    PolicyStore store = load(strict());
    int afterLoad = reloadEvents().size();

    tick();
    store.maybeReload();

    assertEquals(afterLoad, reloadEvents().size());
  }

  @Test
  void anAuditFailureDoesNotInvalidateThePublishedPolicy() throws Exception {
    // A fault in the logging backend during reload audit emission must not undo the published
    // policy.
    TestSupport.writeAcl(aclFile, allow(fileA));
    audit.close(); // replace the capturing appender with one that fails on every emit
    try (ThrowingAuditAppender ignored = ThrowingAuditAppender.install()) {
      PolicyStore store = load(strict());
      assertInstanceOf(AclState.Valid.class, store.current());

      TestSupport.writeAcl(aclFile, allow(fileB));
      tick();
      store.maybeReload();

      AclState.Valid valid = assertInstanceOf(AclState.Valid.class, store.current());
      assertTrue(valid.policy().rulesForUser("alice").get(0).matches(fileB));
    }
  }
}
