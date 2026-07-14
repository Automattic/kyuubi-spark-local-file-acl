package com.automattic.kyuubi.spark.localfileacl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AclYamlLoaderSpec {

  @TempDir Path tempDir;

  private Path root;
  private Path uploadRoot;
  private AclYamlLoader loader;

  @BeforeEach
  void setUp() throws Exception {
    root = TestSupport.real(tempDir);
    uploadRoot = Files.createDirectories(root.resolve("upload"));
    loader = new AclYamlLoader(uploadRoot, null);
  }

  private AclPolicy parse(String yaml) {
    return loader.parse(yaml.getBytes(StandardCharsets.UTF_8));
  }

  @Test
  void loadsUserAndGroupRules() throws Exception {
    Files.writeString(root.resolve("exact.conf"), "x");
    AclPolicy policy =
        parse(
            """
        version: 1
        users:
          alice:
            allow:
              - '%s/alice/*.conf'
        groups:
          data-eng:
            allow:
              - '%s/shared/**'
              - '%s/exact.conf'
        """
                .formatted(root, root, root));
    assertEquals(1, policy.rulesForUser("alice").size());
    assertEquals(2, policy.rulesForGroup("data-eng").size());
    assertEquals(3, policy.ruleCount());
    assertTrue(policy.rulesForUser("bob").isEmpty());
  }

  @Test
  void supportsAllJavaGlobConstructsAndExactPaths() throws Exception {
    Files.createDirectories(root.resolve("d/sub"));
    Files.writeString(root.resolve("d/exact.conf"), "x");
    AclPolicy policy =
        parse(
            """
        version: 1
        users:
          u:
            allow:
              - '%s/d/*.conf'
              - '%s/d/**/deep.jar'
              - '%s/d/runtime-?.properties'
              - '%s/d/[ab].cfg'
              - '%s/d/{one,two}.pem'
              - '%s/d/exact.conf'
        """
                .formatted(root, root, root, root, root, root));
    List<CompiledRule> rules = policy.rulesForUser("u");

    assertTrue(rules.get(0).matches(root.resolve("d/x.conf")));
    assertFalse(rules.get(0).matches(root.resolve("d/sub/x.conf")));
    assertTrue(rules.get(1).matches(root.resolve("d/sub/deeper/deep.jar")));
    assertTrue(rules.get(2).matches(root.resolve("d/runtime-1.properties")));
    assertFalse(rules.get(2).matches(root.resolve("d/runtime-12.properties")));
    assertTrue(rules.get(3).matches(root.resolve("d/a.cfg")));
    assertFalse(rules.get(3).matches(root.resolve("d/c.cfg")));
    assertTrue(rules.get(4).matches(root.resolve("d/one.pem")));
    assertFalse(rules.get(4).matches(root.resolve("d/three.pem")));
    assertTrue(rules.get(5).matches(root.resolve("d/exact.conf")));
    assertFalse(rules.get(5).matches(root.resolve("d/other.conf")));
  }

  @Test
  void exactRulesCanonicalizeSymlinksAtLoadTime() throws Exception {
    Path target = Files.writeString(root.resolve("target.conf"), "x");
    Path link = Files.createSymbolicLink(root.resolve("link.conf"), target);
    AclPolicy policy =
        parse(
            """
        version: 1
        users:
          u:
            allow:
              - '%s'
        """
                .formatted(link));
    // The compiled rule points at the canonical target, matching canonicalized submissions.
    assertTrue(policy.rulesForUser("u").get(0).matches(target.toRealPath()));
  }

  @Test
  void producesImmutableSnapshots() throws Exception {
    Files.writeString(root.resolve("a.conf"), "x");
    AclPolicy policy =
        parse(
            """
        version: 1
        users:
          u:
            allow:
              - '%s/a.conf'
        """
                .formatted(root));
    assertThrows(UnsupportedOperationException.class, () -> policy.userRules().put("x", List.of()));
    assertThrows(
        UnsupportedOperationException.class,
        () -> policy.rulesForUser("u").add(policy.rulesForUser("u").get(0)));
  }

  @Test
  void rejectsMalformedYamlAndUnsupportedVersions() {
    assertThrows(IllegalArgumentException.class, () -> parse("just a string"));
    assertThrows(RuntimeException.class, () -> parse("{unclosed: ["));
    assertThrows(IllegalArgumentException.class, () -> parse("version: 2\n"));
    assertThrows(IllegalArgumentException.class, () -> parse("users: {}\n"));
    assertThrows(IllegalArgumentException.class, () -> parse("version: 1\nunknown_section: {}\n"));
    assertThrows(
        IllegalArgumentException.class,
        () -> parse("version: 1\nusers:\n  u:\n    deny:\n      - '/x'\n"));
    assertThrows(
        IllegalArgumentException.class,
        () -> parse("version: 1\nusers:\n  u:\n    allow: '/not-a-list'\n"));
    assertThrows(
        IllegalArgumentException.class,
        () -> parse("version: 1\nusers:\n  u:\n    allow:\n      - 42\n"));
  }

  @Test
  void rejectsRelativeDotDotSchemeAndInvalidGlobPatterns() {
    assertThrows(IllegalArgumentException.class, () -> parseSinglePattern("relative/path.conf"));
    assertThrows(IllegalArgumentException.class, () -> parseSinglePattern("/a/../b.conf"));
    assertThrows(IllegalArgumentException.class, () -> parseSinglePattern("file:/a/b.conf"));
    assertThrows(IllegalArgumentException.class, () -> parseSinglePattern("hdfs://nn/a.conf"));
    assertThrows(IllegalArgumentException.class, () -> parseSinglePattern("/a/[unclosed"));
  }

  @Test
  void rejectsExactPatternsForMissingFiles() {
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () -> parseSinglePattern(root + "/does-not-exist.conf"));
    assertTrue(e.getMessage().contains("does not resolve"));
  }

  @Test
  void rejectsDuplicateYamlKeys() throws Exception {
    Files.writeString(root.resolve("a.conf"), "x");
    // Duplicate principal: the second alice would silently replace the first.
    assertThrows(
        RuntimeException.class,
        () ->
            parse(
                """
        version: 1
        users:
          alice:
            allow:
              - '%s/a.conf'
          alice:
            allow:
              - '%s/**'
        """
                    .formatted(root, root)));
    // Duplicate 'allow' within one principal.
    assertThrows(
        RuntimeException.class,
        () ->
            parse(
                """
        version: 1
        users:
          alice:
            allow:
              - '%s/a.conf'
            allow:
              - '%s/**'
        """
                    .formatted(root, root)));
  }

  @Test
  void rejectsPatternsTargetingTheUploadRoot() {
    assertThrows(IllegalArgumentException.class, () -> parseSinglePattern(uploadRoot + "/**"));
    assertThrows(
        IllegalArgumentException.class,
        () -> parseSinglePattern(uploadRoot + "/some-batch/file.jar"));
    // Broad patterns above the upload root stay loadable; the engine denies at request time.
    parseSinglePattern(root + "/**");
  }

  @Test
  void readVerifiedRejectsMissingLooseOrUploadRootLocations() throws Exception {
    assertThrows(Exception.class, () -> loader.readVerified(root.resolve("missing.yaml")));

    Path loose = root.resolve("loose.yaml");
    Files.writeString(loose, "version: 1\n");
    Files.setPosixFilePermissions(
        loose,
        EnumSet.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.GROUP_WRITE));
    assertThrows(Exception.class, () -> loader.readVerified(loose));

    Path uploaded = uploadRoot.resolve("acl.yaml");
    TestSupport.writeAcl(uploaded, "version: 1\n");
    assertThrows(Exception.class, () -> loader.readVerified(uploaded));

    Path good = root.resolve("good.yaml");
    TestSupport.writeAcl(good, "version: 1\n");
    assertEquals("version: 1\n", new String(loader.readVerified(good)));
  }

  @Test
  void readVerifiedEnforcesExpectedOwnerAndSizeLimit() throws Exception {
    Path acl = root.resolve("owned.yaml");
    TestSupport.writeAcl(acl, "version: 1\n");

    AclYamlLoader wrongOwner = new AclYamlLoader(uploadRoot, "definitely-not-this-user");
    assertThrows(Exception.class, () -> wrongOwner.readVerified(acl));

    AclYamlLoader rightOwner = new AclYamlLoader(uploadRoot, Files.getOwner(acl).getName());
    assertEquals("version: 1\n", new String(rightOwner.readVerified(acl)));

    Path huge = root.resolve("huge.yaml");
    TestSupport.writeAcl(huge, "# padding\n".repeat(200_000));
    assertThrows(Exception.class, () -> loader.readVerified(huge));
  }

  @Test
  void readVerifiedRejectsFileChangingDuringRead() throws Exception {
    Path acl = root.resolve("growing.yaml");
    TestSupport.writeAcl(acl, "version: 1\n");
    // The hook fires between the pre-read integrity check and the content read, so every
    // attempt observes a size/mtime mismatch and the read is never accepted.
    AclYamlLoader racingLoader =
        new AclYamlLoader(
            uploadRoot,
            null,
            () -> {
              try {
                Files.writeString(acl, "# grew\n", StandardOpenOption.APPEND);
              } catch (IOException e) {
                throw new UncheckedIOException(e);
              }
            });
    IOException e = assertThrows(IOException.class, () -> racingLoader.readVerified(acl));
    assertTrue(e.getMessage().contains("changed while being read"), e.getMessage());
  }

  @Test
  void readVerifiedBoundsAllocationWhenFileGrowsPastTheCapDuringRead() throws Exception {
    Path acl = root.resolve("ballooning.yaml");
    TestSupport.writeAcl(acl, "version: 1\n");
    byte[] filler = new byte[(int) AclYamlLoader.MAX_ACL_BYTES + 1024];
    AclYamlLoader racingLoader =
        new AclYamlLoader(
            uploadRoot,
            null,
            () -> {
              try {
                Files.write(acl, filler, StandardOpenOption.APPEND);
              } catch (IOException e) {
                throw new UncheckedIOException(e);
              }
            });
    // The bounded stream stops at the cap instead of allocating the whole grown file.
    IOException e = assertThrows(IOException.class, () -> racingLoader.readVerified(acl));
    assertTrue(e.getMessage().contains("exceeds"), e.getMessage());
  }

  @Test
  void readVerifiedRejectsWritableAncestorDirectories() throws Exception {
    Path grandParent = Files.createDirectory(root.resolve("grand"));
    Path parent = Files.createDirectory(grandParent.resolve("sub"));
    Path acl = parent.resolve("acl.yaml");
    TestSupport.writeAcl(acl, "version: 1\n");
    // The immediate parent is tight, but a group-writable grandparent still allows an entry swap.
    Files.setPosixFilePermissions(
        grandParent,
        EnumSet.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE,
            PosixFilePermission.GROUP_WRITE,
            PosixFilePermission.GROUP_EXECUTE));
    assertThrows(Exception.class, () -> loader.readVerified(acl));
  }

  @Test
  void readVerifiedRequiresTrustedOwnershipAlongTheAncestorChain() throws Exception {
    Path acl = root.resolve("chain.yaml");
    TestSupport.writeAcl(acl, "version: 1\n");
    // The whole chain (user temp dirs plus root-owned system ancestors) must satisfy
    // "expected owner or root" — this walks all the way to /.
    AclYamlLoader ownedLoader = new AclYamlLoader(uploadRoot, Files.getOwner(acl).getName(), null);
    assertEquals("version: 1\n", new String(ownedLoader.readVerified(acl)));
    // A chain containing directories owned by anyone else is rejected (here every user-owned
    // temp ancestor violates the expectation).
    AclYamlLoader distrustingLoader =
        new AclYamlLoader(uploadRoot, "definitely-not-this-user", null);
    assertThrows(Exception.class, () -> distrustingLoader.readVerified(acl));
  }

  @Test
  void readVerifiedRejectsForeignOwnedAncestorEvenWhenTheFileOwnerIsCorrect() throws Exception {
    Path foreignDir = Files.createDirectory(root.resolve("foreign"));
    Path acl = foreignDir.resolve("acl.yaml");
    TestSupport.writeAcl(acl, "version: 1\n");
    String me = Files.getOwner(acl).getName();
    // Injected owner lookup: the file (and every other ancestor) belongs to the expected owner,
    // but this one 0755-style directory is controlled by someone else — a directory-entry swap
    // vector that must be rejected with the ancestor-specific error.
    AclYamlLoader foreignAncestorLoader =
        new AclYamlLoader(uploadRoot, me, null, path -> path.equals(foreignDir) ? "intruder" : me);
    IOException e = assertThrows(IOException.class, () -> foreignAncestorLoader.readVerified(acl));
    assertTrue(e.getMessage().contains("ancestor directory"), e.getMessage());
    assertTrue(e.getMessage().contains("intruder"), e.getMessage());
  }

  @Test
  void readVerifiedAllowsStickyWorldWritableAncestorsLikeTmp() throws Exception {
    Path sticky = Files.createDirectory(root.resolve("sticky"));
    Path sub = Files.createDirectory(sticky.resolve("sub"));
    Path acl = sub.resolve("acl.yaml");
    TestSupport.writeAcl(acl, "version: 1\n");
    // /tmp-style 1777: world-writable but sticky, so entries cannot be swapped by other users.
    Files.setAttribute(sticky, "unix:mode", 01777);
    assertEquals("version: 1\n", new String(loader.readVerified(acl)));

    // Without the sticky bit the same mode is rejected.
    Files.setAttribute(sticky, "unix:mode", 0777);
    assertThrows(Exception.class, () -> loader.readVerified(acl));
  }

  @Test
  void readVerifiedRejectsLooseDirectoryPermissions() throws Exception {
    Path looseDir = Files.createDirectory(root.resolve("loose-dir"));
    Path acl = looseDir.resolve("acl.yaml");
    TestSupport.writeAcl(acl, "version: 1\n");
    Files.setPosixFilePermissions(
        looseDir,
        EnumSet.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE,
            PosixFilePermission.OTHERS_WRITE,
            PosixFilePermission.OTHERS_EXECUTE));
    assertThrows(Exception.class, () -> loader.readVerified(acl));
  }

  private void parseSinglePattern(String pattern) {
    parse(
        """
        version: 1
        users:
          u:
            allow:
              - '%s'
        """
            .formatted(pattern));
  }
}
