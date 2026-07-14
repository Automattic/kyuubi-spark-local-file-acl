package com.automattic.kyuubi.spark.localfileacl;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.apache.kyuubi.KyuubiException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class UploadIsolationSpec {

  @TempDir Path tempDir;

  private final String currentBatchId = UUID.randomUUID().toString();
  private final String otherBatchId = UUID.randomUUID().toString();

  private Path root;
  private Path uploadRoot;
  private Path currentUpload;
  private Path otherUpload;
  private LocalFileAclEngine engine;

  @BeforeEach
  void setUp() throws Exception {
    root = TestSupport.real(tempDir);
    uploadRoot = Files.createDirectories(root.resolve("upload"));
    currentUpload = TestSupport.stageUpload(uploadRoot, currentBatchId, "job.jar");
    otherUpload = TestSupport.stageUpload(uploadRoot, otherBatchId, "job.jar");
    Path aclFile = root.resolve("acl.yaml");
    // A deliberately broad grant covering the whole temp tree, including the upload root.
    TestSupport.writeAcl(
        aclFile,
        """
        version: 1
        users:
          alice:
            allow:
              - '%s/**'
        """
            .formatted(root));
    engine = TestSupport.newEngine(aclFile, uploadRoot, user -> Set.of(), new MutableClock());
  }

  private Map<String, String> uploadedConf(String batchId, String path) {
    return TestSupport.uploadedConf(batchId, path);
  }

  @Test
  void allowsFilesUploadedByTheCurrentBatch() {
    engine.validate("alice", uploadedConf(currentBatchId, currentUpload.toString()));
    // The exemption is not ACL-based: a user with no rules at all still gets it.
    engine.validate("nobody", uploadedConf(currentBatchId, currentUpload.toString()));
  }

  @Test
  void deniesOtherBatchesUploadsEvenWithBroadAclGrant() {
    // alice's '/**' glob matches the other batch's file, but step-2 denial is unconditional.
    KyuubiException e =
        assertThrows(
            KyuubiException.class,
            () -> engine.validate("alice", uploadedConf(currentBatchId, otherUpload.toString())));
    assertTrue(e.getMessage().contains("upload root"));
  }

  @Test
  void deniesPathsElsewhereUnderTheSharedUploadRoot() throws Exception {
    Path stray = Files.writeString(uploadRoot.resolve("stray.jar"), "x");
    assertThrows(
        KyuubiException.class,
        () -> engine.validate("alice", uploadedConf(currentBatchId, stray.toString())));
  }

  @Test
  void requiresUploadFlagAndValidBatchId() {
    // Missing uploaded flag.
    assertThrows(
        KyuubiException.class,
        () ->
            engine.validate(
                "nobody",
                Map.of(
                    "kyuubi.batch.id", currentBatchId, "spark.files", currentUpload.toString())));
    // Missing batch id.
    assertThrows(
        KyuubiException.class,
        () ->
            engine.validate(
                "nobody",
                Map.of(
                    "kyuubi.batch.resource.uploaded",
                    "true",
                    "spark.files",
                    currentUpload.toString())));
    // Batch id that is not a UUID cannot address an upload directory.
    assertThrows(
        KyuubiException.class,
        () ->
            engine.validate(
                "nobody", uploadedConf("../" + currentBatchId, currentUpload.toString())));
  }

  @Test
  void rejectsStagedUploadWhoseCanonicalPathEscapesTheBatchDirectory() throws Exception {
    Path outside = Files.writeString(root.resolve("outside.jar"), "x");
    Path link =
        Files.createSymbolicLink(uploadRoot.resolve(currentBatchId).resolve("escape.jar"), outside);
    // Canonicalizes outside the upload root, so the exemption does not apply; for a user
    // without a matching ACL rule this is denied regardless of the staged filename.
    assertThrows(
        KyuubiException.class,
        () -> engine.validate("nobody", uploadedConf(currentBatchId, link.toString())));
  }
}
