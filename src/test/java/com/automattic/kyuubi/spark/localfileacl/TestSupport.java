package com.automattic.kyuubi.spark.localfileacl;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.Groups;
import org.apache.hadoop.security.UserGroupInformation;

final class TestSupport {

  static final Set<PosixFilePermission> OWNER_ONLY =
      Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

  /** One field of a logfmt record: {@code key=value} or {@code key="quoted, escaped value"}. */
  private static final Pattern LOGFMT_FIELD =
      Pattern.compile("(\\w+)=(?:\"((?:[^\"\\\\]|\\\\.)*)\"|(\\S+))");

  private TestSupport() {}

  /** Parses an audit logfmt line into its fields, the way an operator's log pipeline would. */
  static Map<String, String> parseLogfmt(String record) {
    Map<String, String> parsed = new LinkedHashMap<>();
    Matcher matcher = LOGFMT_FIELD.matcher(record);
    while (matcher.find()) {
      parsed.put(matcher.group(1), matcher.group(2) != null ? matcher.group(2) : matcher.group(3));
    }
    return parsed;
  }

  /** Writes the ACL with owner-only permissions, as the loader's file check requires. */
  static void writeAcl(Path file, String yaml) throws IOException {
    Files.writeString(file, yaml);
    Files.setPosixFilePermissions(file, OWNER_ONLY);
  }

  /** A version-2 ACL document granting each principal (in insertion order) its listed paths. */
  static String usersAcl(Map<String, List<Path>> rules) {
    StringBuilder yaml = new StringBuilder("version: 2\nusers:\n");
    rules.forEach(
        (principal, paths) -> {
          yaml.append("  ").append(principal).append(":\n");
          paths.forEach(path -> yaml.append("    - '").append(path).append("'\n"));
        });
    return yaml.toString();
  }

  /**
   * Options for the suite's glob-heavy fixtures, which opt into wildcard matching explicitly. The
   * production defaults (wildcards off, fail on missing files) are covered by {@link
   * PluginSettingsSpec} and {@link AclYamlLoaderSpec}.
   */
  static AclYamlLoader.Options options(Path uploadRoot) {
    return new AclYamlLoader.Options(uploadRoot, null, true, true);
  }

  static PolicyStore newLoadedStore(
      Path aclFile, Path uploadRoot, Duration interval, MutableClock clock) {
    return newLoadedStore(aclFile, options(uploadRoot), interval, clock);
  }

  static PolicyStore newLoadedStore(
      Path aclFile, AclYamlLoader.Options options, Duration interval, MutableClock clock) {
    PolicyStore store =
        new PolicyStore(aclFile, new AclYamlLoader(options), interval, clock::nanos);
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
