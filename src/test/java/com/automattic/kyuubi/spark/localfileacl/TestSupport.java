package com.automattic.kyuubi.spark.localfileacl;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.Set;

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
    PolicyStore store = new PolicyStore(
        aclFile, new AclYamlLoader(uploadRoot, null), interval, clock, clock::nanos);
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
}
