package com.automattic.kyuubi.spark.localfileacl;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.apache.kyuubi.KyuubiException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** End-to-end contract of the zero-arg advisor wired purely from JVM system properties. */
class AdvisorContractSpec {

  @TempDir Path tempDir;

  private Path root;
  private Path allowedFile;
  private Path secretFile;

  @BeforeEach
  void setUp() throws Exception {
    root = TestSupport.real(tempDir);
    Path uploadRoot = Files.createDirectories(root.resolve("upload"));
    allowedFile =
        Files.writeString(Files.createDirectories(root.resolve("res")).resolve("app.conf"), "x");
    secretFile = Files.writeString(root.resolve("secret.keytab"), "x");
    Path aclFile = root.resolve("acl.yaml");
    TestSupport.writeAcl(
        aclFile,
        """
        version: 1
        users:
          alice:
            allow:
              - '%s/res/*.conf'
        """
            .formatted(root));
    System.setProperty(PluginSettings.RULES_FILE_PROP, aclFile.toString());
    System.setProperty(PluginSettings.UPLOAD_ROOT_PROP, uploadRoot.toString());
    System.setProperty(PluginSettings.RELOAD_INTERVAL_PROP, "PT60S");
  }

  @AfterEach
  void clearProperties() {
    System.clearProperty(PluginSettings.RULES_FILE_PROP);
    System.clearProperty(PluginSettings.UPLOAD_ROOT_PROP);
    System.clearProperty(PluginSettings.RELOAD_INTERVAL_PROP);
    System.clearProperty(PluginSettings.EXTRA_KEYS_PROP);
    System.clearProperty(PluginSettings.EXCLUDED_KEYS_PROP);
  }

  @Test
  void authorizedSubmissionReturnsEmptyOverlay() {
    SparkLocalFileAclAdvisor advisor = new SparkLocalFileAclAdvisor();
    Map<String, String> sessionConf =
        new HashMap<>(
            Map.of(
                "spark.files", allowedFile.toString(),
                "spark.jars", "hdfs://nn/lib.jar",
                "spark.executor.memory", "4g"));
    Map<String, String> before = Map.copyOf(sessionConf);

    Map<String, String> overlay = advisor.getConfOverlay("alice", sessionConf);

    assertTrue(overlay.isEmpty(), "authorized submissions must leave the configuration unchanged");
    assertTrue(sessionConf.equals(before), "advisor must not mutate the session configuration");
    // Plugin JVM settings never leak into the effective Spark configuration.
    assertTrue(
        sessionConf.keySet().stream().noneMatch(key -> key.startsWith("kyuubi.local.file.acl.")));
  }

  @Test
  void unauthorizedSubmissionThrowsKyuubiException() {
    SparkLocalFileAclAdvisor advisor = new SparkLocalFileAclAdvisor();
    KyuubiException e =
        assertThrows(
            KyuubiException.class,
            () -> advisor.getConfOverlay("alice", Map.of("spark.files", secretFile.toString())));
    assertTrue(e.getMessage().contains("alice"));
    assertTrue(e.getMessage().contains(secretFile.toString()));
  }

  @Test
  void escapeHatchPropertiesArehonored() throws Exception {
    System.setProperty(PluginSettings.EXTRA_KEYS_PROP, "spark.custom.files:list");
    System.setProperty(PluginSettings.EXCLUDED_KEYS_PROP, "spark.yarn.keytab");
    SparkLocalFileAclAdvisor advisor = new SparkLocalFileAclAdvisor();

    // Extra key policed: unauthorized local file rejected.
    assertThrows(
        KyuubiException.class,
        () -> advisor.getConfOverlay("alice", Map.of("spark.custom.files", secretFile.toString())));
    // Excluded key ignored even though it is a default.
    advisor.getConfOverlay("alice", Map.of("spark.yarn.keytab", secretFile.toString()));
  }

  @Test
  void uploadRootBehindSymlinkedAncestorStillIsolatesUploads() throws Exception {
    Path realWork = Files.createDirectories(root.resolve("real-work"));
    Path linkedWork = Files.createSymbolicLink(root.resolve("linked-work"), realWork);
    // Configure the not-yet-existing upload root through the symlinked ancestor; the advisor
    // must create and canonicalize it so upload paths keep a matching prefix.
    System.setProperty(PluginSettings.UPLOAD_ROOT_PROP, linkedWork.resolve("upload").toString());
    SparkLocalFileAclAdvisor advisor = new SparkLocalFileAclAdvisor();

    Path staged =
        Files.writeString(
            Files.createDirectories(
                    realWork.resolve("upload").resolve(UUID.randomUUID().toString()))
                .resolve("other.jar"),
            "x");
    KyuubiException e =
        assertThrows(
            KyuubiException.class,
            () -> advisor.getConfOverlay("alice", Map.of("spark.files", staged.toString())));
    // Denied specifically by cross-batch upload isolation, not by a generic no-rule miss —
    // proving the canonicalized upload root still recognized the resource as an upload.
    assertTrue(e.getMessage().contains("upload root"), e.getMessage());
  }

  @Test
  void startupFailsOnMalformedEscapeHatchOrMissingAcl() {
    System.setProperty(PluginSettings.EXTRA_KEYS_PROP, "spark.custom.files:banana");
    assertThrows(RuntimeException.class, SparkLocalFileAclAdvisor::new);
    System.clearProperty(PluginSettings.EXTRA_KEYS_PROP);

    System.setProperty(PluginSettings.RULES_FILE_PROP, root.resolve("nope.yaml").toString());
    assertThrows(RuntimeException.class, SparkLocalFileAclAdvisor::new);
  }
}
