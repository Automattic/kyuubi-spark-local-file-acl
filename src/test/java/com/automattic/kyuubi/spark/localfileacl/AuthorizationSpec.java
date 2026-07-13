package com.automattic.kyuubi.spark.localfileacl;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

import org.apache.kyuubi.KyuubiException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuthorizationSpec {

  @TempDir
  Path tempDir;

  private Path root;
  private Path uploadRoot;
  private Path aclFile;
  private Path aliceFile;
  private Path sharedFile;
  private Path adminFile;

  @BeforeEach
  void setUp() throws Exception {
    root = TestSupport.real(tempDir);
    uploadRoot = Files.createDirectories(root.resolve("upload"));
    aclFile = root.resolve("acl.yaml");
    aliceFile = Files.writeString(
        Files.createDirectories(root.resolve("alice")).resolve("app.conf"), "x");
    sharedFile = Files.writeString(
        Files.createDirectories(root.resolve("shared")).resolve("common.properties"), "x");
    adminFile = Files.writeString(
        Files.createDirectories(root.resolve("admin")).resolve("secret.conf"), "x");
    TestSupport.writeAcl(aclFile, """
        version: 1
        users:
          alice:
            allow:
              - '%s/alice/*.conf'
        groups:
          data-eng:
            allow:
              - '%s/shared/*.properties'
          admins:
            allow:
              - '%s/admin/**'
        """.formatted(root, root, root));
  }

  private LocalFileAclEngine engine(GroupResolver resolver) {
    return TestSupport.newEngine(aclFile, uploadRoot, resolver, new MutableClock());
  }

  private static GroupResolver groups(String... names) {
    return user -> Set.of(names);
  }

  @Test
  void authorizesDirectUsernameGrant() {
    engine(groups()).validate("alice", Map.of("spark.files", aliceFile.toString()));
  }

  @Test
  void authorizesPrimaryAndSupplementaryGroupGrants() {
    engine(groups("data-eng")).validate("bob", Map.of("spark.files", sharedFile.toString()));
    engine(groups("staff", "admins"))
        .validate("carol", Map.of("spark.files", adminFile.toString()));
  }

  @Test
  void unionsGrantsAcrossGroupsAndUsername() {
    LocalFileAclEngine engine = engine(groups("data-eng", "admins"));
    engine.validate("alice", Map.of(
        "spark.files", aliceFile + "," + sharedFile,
        "spark.jars", adminFile.toString()));
  }

  @Test
  void deniesUserWithNoMatchingPrincipal() {
    KyuubiException e = assertThrows(KyuubiException.class,
        () -> engine(groups("staff")).validate("mallory",
            Map.of("spark.files", aliceFile.toString())));
    assertTrue(e.getMessage().contains("mallory"));
    assertTrue(e.getMessage().contains("spark.files"));
  }

  @Test
  void emptyGroupSetStillHonorsUsernameRules() {
    engine(groups()).validate("alice", Map.of("spark.files", aliceFile.toString()));
    assertThrows(KyuubiException.class,
        () -> engine(groups()).validate("bob", Map.of("spark.files", sharedFile.toString())));
  }

  @Test
  void failsClosedWhenGroupResolutionFails() {
    GroupResolver failing = user -> {
      throw new IllegalStateException("LDAP down");
    };
    KyuubiException e = assertThrows(KyuubiException.class,
        () -> engine(failing).validate("bob", Map.of("spark.files", sharedFile.toString())));
    assertTrue(e.getMessage().contains("group resolution failed"));
    // Direct username rules never need group resolution.
    engine(failing).validate("alice", Map.of("spark.files", aliceFile.toString()));
  }

  @Test
  void rejectsWholeSubmissionWhenAnyListEntryIsUnauthorized() {
    assertThrows(KyuubiException.class,
        () -> engine(groups()).validate("alice",
            Map.of("spark.files", aliceFile + "," + adminFile)));
  }

  @Test
  void validatesUnqualifiedAliasesIndependentlyOfQualifiedKeys() {
    // Both the qualified and unqualified alias are policed and validated as separate entries.
    engine(groups()).validate("alice", Map.of(
        "spark.files", aliceFile.toString(),
        "files", aliceFile.toString()));
    assertThrows(KyuubiException.class,
        () -> engine(groups()).validate("alice", Map.of(
            "spark.files", aliceFile.toString(),
            "files", adminFile.toString())));
  }

  @Test
  void validatesScalarKeytabWithoutListParsing() throws Exception {
    Path keytab = Files.writeString(root.resolve("alice").resolve("svc.conf"), "x");
    engine(groups()).validate("alice", Map.of("spark.kerberos.keytab", keytab.toString()));
    assertThrows(KyuubiException.class,
        () -> engine(groups()).validate("alice",
            Map.of("spark.yarn.keytab", adminFile.toString())));
  }

  @Test
  void ignoresRemoteResourcesAndUnpolicedKeys() {
    engine(groups()).validate("nobody", Map.of(
        "spark.files", "hdfs://nn/x.jar,s3a://bucket/y.jar",
        "spark.executor.memory", "4g",
        "spark.kubernetes.file.upload.path", adminFile.toString()));
  }

  @Test
  void preventsSymlinkEscapeFromAllowedTree() throws Exception {
    Path link = Files.createSymbolicLink(root.resolve("alice").resolve("escape.conf"), adminFile);
    // The canonical target is outside alice's allowed tree, so the glob no longer matches.
    assertThrows(KyuubiException.class,
        () -> engine(groups()).validate("alice", Map.of("spark.files", link.toString())));
  }

  @Test
  void deniesMalformedLocalValuesWithContext() {
    KyuubiException e = assertThrows(KyuubiException.class,
        () -> engine(groups()).validate("alice",
            Map.of("spark.files", root + "/alice/*.conf")));
    assertTrue(e.getMessage().contains("glob"));
  }
}
