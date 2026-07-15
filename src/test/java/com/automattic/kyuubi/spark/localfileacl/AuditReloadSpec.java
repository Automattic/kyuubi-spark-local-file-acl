package com.automattic.kyuubi.spark.localfileacl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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

/** The reload lifecycle stream: one audit event whenever a reload changes the published policy. */
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
    StringBuilder yaml = new StringBuilder("version: 2\nusers:\n  alice:\n");
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
  void initialLoadEmitsALoadedEventAtInfo() throws Exception {
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
  void aRuntimeChangeNamesTheAddedAndRemovedRules() throws Exception {
    TestSupport.writeAcl(aclFile, allow(fileA));
    PolicyStore store = load(strict());

    TestSupport.writeAcl(aclFile, allow(fileB));
    tick();
    store.maybeReload();

    Map<String, String> event = lastReload();
    assertEquals("changed", event.get("outcome"));
    assertTrue(event.get("added").contains("user:alice:" + fileB), event.get("added"));
    assertTrue(event.get("removed").contains("user:alice:" + fileA), event.get("removed"));
    // A real change carries the digest transition.
    assertNotEqualsDigests(event);
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

    // Loaded with the missing rule omitted.
    Map<String, String> loaded = lastReload();
    assertEquals("loaded", loaded.get("outcome"));
    assertEquals("1", loaded.get("unresolved"));

    // The file appears; the YAML is not touched, so the digest is unchanged.
    Files.writeString(later, "x");
    tick();
    store.maybeReload();

    Map<String, String> event = lastReload();
    assertEquals("changed", event.get("outcome"));
    assertEquals("0", event.get("unresolved"));
    assertTrue(event.get("resolved").contains(later.toString()), event.get("resolved"));
    assertTrue(event.get("added").contains("user:alice:" + later), event.get("added"));
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

    // Still invalid on the next interval: no second event.
    int afterInvalidation = reloadEvents().size();
    tick();
    store.maybeReload();
    assertEquals(afterInvalidation, reloadEvents().size());
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
}
