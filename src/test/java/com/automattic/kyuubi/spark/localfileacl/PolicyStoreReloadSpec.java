package com.automattic.kyuubi.spark.localfileacl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.kyuubi.KyuubiException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PolicyStoreReloadSpec {

  private static final Duration INTERVAL = Duration.ofSeconds(60);

  @TempDir Path tempDir;

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
    TestSupport.writeAcl(aclFile, allowOnly(fileA));
  }

  private String allowOnly(Path path) {
    return """
        version: 1
        users:
          alice:
            allow:
              - '%s'
        """
        .formatted(path);
  }

  private PolicyStore newStore() {
    return TestSupport.newLoadedStore(aclFile, uploadRoot, INTERVAL, clock);
  }

  private LocalFileAclEngine engineOn(PolicyStore store) {
    return new LocalFileAclEngine(
        PolicedKeys.fromSettings(null, null), store, user -> Set.of(), uploadRoot);
  }

  private void tickPastInterval() {
    clock.advance(INTERVAL.plusSeconds(1));
  }

  @Test
  void initialLoadFailsOnInvalidPolicy() throws Exception {
    TestSupport.writeAcl(aclFile, "version: 99\n");
    assertThrows(IllegalStateException.class, this::newStore);
  }

  @Test
  void activatesChangedPolicyAndRevokesAccessWithoutRestart() throws Exception {
    PolicyStore store = newStore();
    LocalFileAclEngine engine = engineOn(store);
    engine.validate("alice", Map.of("spark.files", fileA.toString()));

    TestSupport.writeAcl(aclFile, allowOnly(fileB));
    // Interval not elapsed yet: old policy still active.
    engine.validate("alice", Map.of("spark.files", fileA.toString()));

    tickPastInterval();
    engine.validate("alice", Map.of("spark.files", fileB.toString()));
    assertThrows(
        KyuubiException.class,
        () -> engine.validate("alice", Map.of("spark.files", fileA.toString())));
  }

  @Test
  void skipsReparsingWhenDigestIsUnchanged() throws Exception {
    PolicyStore store = newStore();
    AclState.Valid initial = assertInstanceOf(AclState.Valid.class, store.current());

    // Touch the file (mtime changes, content identical) and pass the interval.
    Files.setLastModifiedTime(aclFile, FileTime.fromMillis(System.currentTimeMillis() + 5_000));
    tickPastInterval();
    store.maybeReload();

    AclState.Valid after = assertInstanceOf(AclState.Valid.class, store.current());
    // The same compiled policy instance proves the content was not reparsed.
    assertSame(initial.policy(), after.policy());
    assertEquals(initial.digest(), after.digest());
  }

  @Test
  void detectsContentChangeEvenWhenModificationTimeIsUnchanged() throws Exception {
    PolicyStore store = newStore();
    FileTime originalTime = Files.getLastModifiedTime(aclFile);
    String initialDigest = assertInstanceOf(AclState.Valid.class, store.current()).digest();

    TestSupport.writeAcl(aclFile, allowOnly(fileB));
    Files.setLastModifiedTime(aclFile, originalTime);
    tickPastInterval();
    store.maybeReload();

    AclState.Valid after = assertInstanceOf(AclState.Valid.class, store.current());
    assertNotEquals(initialDigest, after.digest());
    LocalFileAclEngine engine = engineOn(store);
    engine.validate("alice", Map.of("spark.files", fileB.toString()));
    assertThrows(
        KyuubiException.class,
        () -> engine.validate("alice", Map.of("spark.files", fileA.toString())));
  }

  @Test
  void transitionsToInvalidAndRejectsLocalResources() throws Exception {
    PolicyStore store = newStore();
    LocalFileAclEngine engine = engineOn(store);

    TestSupport.writeAcl(aclFile, "not: [valid");
    tickPastInterval();
    store.maybeReload();
    assertInstanceOf(AclState.Invalid.class, store.current());

    KyuubiException e =
        assertThrows(
            KyuubiException.class,
            () -> engine.validate("alice", Map.of("spark.files", fileA.toString())));
    assertTrue(e.getMessage().contains("invalid"));

    // Submissions without policed keys or with remote-only resources stay unaffected.
    engine.validate("alice", Map.of("spark.executor.memory", "4g"));
    engine.validate("alice", Map.of("spark.files", "hdfs://nn/x.jar"));
  }

  @Test
  void reloadFollowsMonotonicTimeWhenWallClockStepsBackwards() throws Exception {
    PolicyStore store = newStore();
    LocalFileAclEngine engine = engineOn(store);
    TestSupport.writeAcl(aclFile, allowOnly(fileB));

    // Simulate an NTP step: wall time jumps an hour into the past while monotonic time keeps
    // advancing past the reload interval. Wall-clock scheduling would postpone this reload
    // (and the revocation of fileA) until wall time caught back up.
    clock.rewindWallClock(Duration.ofHours(1));
    clock.advance(INTERVAL.plusSeconds(1));
    store.maybeReload();

    engine.validate("alice", Map.of("spark.files", fileB.toString()));
    assertThrows(
        KyuubiException.class,
        () -> engine.validate("alice", Map.of("spark.files", fileA.toString())));
  }

  @Test
  void currentBatchUploadsRemainExemptWhileAclStateIsInvalid() throws Exception {
    String batchId = UUID.randomUUID().toString();
    Path staged = TestSupport.stageUpload(uploadRoot, batchId, "job.jar");
    PolicyStore store = newStore();
    LocalFileAclEngine engine = engineOn(store);

    TestSupport.writeAcl(aclFile, "not: [valid");
    tickPastInterval();
    store.maybeReload();
    assertInstanceOf(AclState.Invalid.class, store.current());

    // The exemption never consults ACL rules, so an invalid policy does not fail batches that
    // reference only their own uploads...
    engine.validate("alice", TestSupport.uploadedConf(batchId, staged.toString()));
    // ...while ACL-authorized local resources are still rejected.
    assertThrows(
        KyuubiException.class,
        () -> engine.validate("alice", Map.of("spark.files", fileA.toString())));
  }

  @Test
  void transitionsToInvalidWhenFileIsMissingOrHasLoosePermissions() throws Exception {
    PolicyStore store = newStore();

    Files.delete(aclFile);
    tickPastInterval();
    store.maybeReload();
    assertInstanceOf(AclState.Invalid.class, store.current());

    TestSupport.writeAcl(aclFile, allowOnly(fileA));
    Files.setPosixFilePermissions(
        aclFile,
        Set.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OTHERS_WRITE));
    tickPastInterval();
    store.maybeReload();
    assertInstanceOf(AclState.Invalid.class, store.current());
  }

  @Test
  void recoversAtomicallyFromInvalidState() throws Exception {
    PolicyStore store = newStore();
    LocalFileAclEngine engine = engineOn(store);

    TestSupport.writeAcl(aclFile, "garbage: [");
    tickPastInterval();
    store.maybeReload();
    assertInstanceOf(AclState.Invalid.class, store.current());

    // Same digest as the last processed content must not suppress recovery.
    TestSupport.writeAcl(aclFile, allowOnly(fileA));
    tickPastInterval();
    store.maybeReload();
    assertInstanceOf(AclState.Valid.class, store.current());
    engine.validate("alice", Map.of("spark.files", fileA.toString()));
  }

  @Test
  void invalidGlobInReloadInvalidatesState() throws Exception {
    PolicyStore store = newStore();
    TestSupport.writeAcl(aclFile, allowOnly(Path.of(root + "/[unclosed")));
    tickPastInterval();
    store.maybeReload();
    assertInstanceOf(AclState.Invalid.class, store.current());
  }

  @Test
  void submissionIsAuthorizedAgainstOneSnapshotEvenWhenReloadedMidValidation() throws Exception {
    // v1 grants bob's group both files.
    TestSupport.writeAcl(
        aclFile,
        """
        version: 1
        groups:
          g:
            allow:
              - '%s'
              - '%s'
        """
            .formatted(fileA, fileB));
    PolicyStore store = newStore();
    // Group resolution runs while the first resource is being authorized — after the engine
    // captured its snapshot. Swap in a policy that grants nothing and force a reload.
    GroupResolver swappingResolver =
        user -> {
          TestSupport.writeAcl(aclFile, "version: 1\n");
          tickPastInterval();
          store.maybeReload();
          return Set.of("g");
        };
    LocalFileAclEngine engine =
        new LocalFileAclEngine(
            PolicedKeys.fromSettings(null, null), store, swappingResolver, uploadRoot);

    // Both entries pass because the whole submission is judged by the captured v1 snapshot,
    // never half by v1 and half by the revoked policy.
    engine.validate("bob", Map.of("spark.files", fileA + "," + fileB));

    // The revocation took effect for subsequent submissions.
    assertThrows(
        KyuubiException.class,
        () -> engine.validate("bob", Map.of("spark.files", fileA.toString())));
  }

  @Test
  void unresolvedExactRuleActivatesWhenItsFileAppearsWithoutAnAclEdit() throws Exception {
    Path later = root.resolve("later.conf");
    TestSupport.writeAcl(
        aclFile,
        """
        version: 1
        users:
          alice:
            allow:
              - '%s'
              - '%s'
        """
            .formatted(fileA, later));
    PolicyStore store =
        TestSupport.newLoadedStore(
            aclFile, new AclYamlLoader.Options(uploadRoot, null, false, false), INTERVAL, clock);
    LocalFileAclEngine engine = engineOn(store);

    // The policy is valid with the missing rule omitted, and it authorizes nothing.
    AclState.Valid lenient = assertInstanceOf(AclState.Valid.class, store.current());
    assertEquals(1, lenient.policy().ruleCount());
    assertEquals(Set.of(later), lenient.policy().unresolvedPaths());

    // While the file is still missing, the unchanged digest keeps skipping the reparse — no
    // churn, and no ERROR re-logged every interval.
    tickPastInterval();
    store.maybeReload();
    assertSame(lenient.policy(), assertInstanceOf(AclState.Valid.class, store.current()).policy());

    Files.writeString(later, "appeared");
    // Not yet reloaded: the snapshot the engine holds still omits the rule.
    assertThrows(
        KyuubiException.class,
        () -> engine.validate("alice", Map.of("spark.files", later.toString())));

    tickPastInterval();
    store.maybeReload();

    // The digest never changed, so activation came from the forced reparse, which canonicalized
    // the path and re-ran every policy check.
    AclState.Valid activated = assertInstanceOf(AclState.Valid.class, store.current());
    assertEquals(lenient.digest(), activated.digest());
    assertEquals(2, activated.policy().ruleCount());
    assertTrue(activated.policy().unresolvedPaths().isEmpty());
    engine.validate("alice", Map.of("spark.files", later.toString()));
  }

  @Test
  void unresolvedPathTurningIntoABrokenPathInvalidatesInsteadOfLingering() throws Exception {
    Path later = root.resolve("later.conf");
    TestSupport.writeAcl(
        aclFile,
        """
        version: 1
        users:
          alice:
            allow:
              - '%s'
              - '%s'
        """
            .formatted(fileA, later));
    PolicyStore store =
        TestSupport.newLoadedStore(
            aclFile, new AclYamlLoader.Options(uploadRoot, null, false, false), INTERVAL, clock);
    assertEquals(
        Set.of(later),
        assertInstanceOf(AclState.Valid.class, store.current()).policy().unresolvedPaths());

    // The path stops being merely absent and becomes a symlink loop: the loader tolerates only a
    // genuinely missing file, so probing must force a reparse rather than read this as "still
    // missing" and keep serving a policy the loader would now reject.
    Path partner = root.resolve("loop-partner.conf");
    Files.createSymbolicLink(later, partner);
    Files.createSymbolicLink(partner, later);
    tickPastInterval();
    store.maybeReload();

    assertInstanceOf(AclState.Invalid.class, store.current());
  }

  @Test
  void concurrentReadersOnlyObserveCompleteSnapshots() throws Exception {
    PolicyStore store = newStore();
    int readers = 4;
    CountDownLatch start = new CountDownLatch(1);
    CountDownLatch done = new CountDownLatch(readers);
    AtomicReference<Throwable> failure = new AtomicReference<>();
    List<Thread> threads = new ArrayList<>();
    for (int i = 0; i < readers; i++) {
      Thread thread =
          new Thread(
              () -> {
                try {
                  start.await();
                  for (int n = 0; n < 500; n++) {
                    AclState state = store.current();
                    if (state instanceof AclState.Valid valid) {
                      // A published snapshot is always fully compiled.
                      assertEquals(1, valid.policy().ruleCount());
                      assertTrue(
                          valid.policy().rulesForUser("alice").get(0).matches(fileA)
                              || valid.policy().rulesForUser("alice").get(0).matches(fileB));
                    }
                  }
                } catch (Throwable t) {
                  failure.set(t);
                } finally {
                  done.countDown();
                }
              });
      threads.add(thread);
      thread.start();
    }
    start.countDown();
    for (int n = 0; n < 20; n++) {
      TestSupport.writeAcl(aclFile, allowOnly(n % 2 == 0 ? fileB : fileA));
      tickPastInterval();
      store.maybeReload();
    }
    done.await();
    if (failure.get() != null) {
      throw new AssertionError(failure.get());
    }
  }
}
