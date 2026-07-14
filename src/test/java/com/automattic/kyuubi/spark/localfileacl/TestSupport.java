package com.automattic.kyuubi.spark.localfileacl;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.Groups;
import org.apache.hadoop.security.UserGroupInformation;

final class TestSupport {

  static final Set<PosixFilePermission> OWNER_ONLY =
      Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

  private TestSupport() {}

  /** Writes the ACL with owner-only permissions, as the loader's file check requires. */
  static void writeAcl(Path file, String yaml) throws IOException {
    Files.writeString(file, yaml);
    Files.setPosixFilePermissions(file, OWNER_ONLY);
  }

  static PolicyStore newLoadedStore(
      Path aclFile, Path uploadRoot, Duration interval, MutableClock clock) {
    PolicyStore store =
        new PolicyStore(aclFile, new AclYamlLoader(uploadRoot, null), interval, clock::nanos);
    store.initialLoad();
    return store;
  }

  static LocalFileAclEngine newEngine(
      Path aclFile, Path uploadRoot, GroupResolver groupResolver, MutableClock clock) {
    PolicyStore store = newLoadedStore(aclFile, uploadRoot, Duration.ofSeconds(60), clock);
    return new LocalFileAclEngine(
        PolicedKeys.fromSettings(null, null), store, groupResolver, uploadRoot);
  }

  /** Canonicalized temp dir (macOS temp dirs live behind the /var -> /private/var symlink). */
  static Path real(Path dir) throws IOException {
    return dir.toRealPath();
  }

  /** Stages a file as if uploaded by the given batch: {@code <uploadRoot>/<batchId>/<fileName>}. */
  static Path stageUpload(Path uploadRoot, String batchId, String fileName) throws IOException {
    return Files.writeString(
        Files.createDirectories(uploadRoot.resolve(batchId)).resolve(fileName), "x");
  }

  /** Session conf carrying Kyuubi's reserved upload keys plus the submitted resource. */
  static Map<String, String> uploadedConf(String batchId, String path) {
    return Map.of(
        "kyuubi.batch.resource.uploaded", "true",
        "kyuubi.batch.id", batchId,
        "spark.files", path);
  }

  /**
   * Installs a Hadoop group mapping JVM-wide. The Groups singleton must be replaced BEFORE {@code
   * setConfiguration}: UGI initialization captures {@code
   * Groups.getUserToGroupsMappingService(conf)}, which returns the existing singleton if any
   * earlier spec already created one.
   */
  static void installHadoopGroupMapping(Configuration conf) {
    UserGroupInformation.reset();
    Groups.getUserToGroupsMappingServiceWithLoadedConfiguration(conf);
    UserGroupInformation.setConfiguration(conf);
  }
}
