package com.automattic.kyuubi.spark.localfileacl;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.apache.kyuubi.KyuubiException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.automattic.kyuubi.spark.localfileacl.LocalResourceParser.LocalResource;

/**
 * Validates every policed local resource in a session configuration. A single unauthorized
 * resource rejects the complete submission by throwing {@link KyuubiException}, which aborts
 * Kyuubi session construction before {@code spark-submit} is assembled.
 */
public final class LocalFileAclEngine {

  private static final Logger LOG = LoggerFactory.getLogger(LocalFileAclEngine.class);

  static final String BATCH_RESOURCE_UPLOADED_KEY = "kyuubi.batch.resource.uploaded";
  static final String BATCH_ID_KEY = "kyuubi.batch.id";

  private final PolicedKeys policedKeys;
  private final PolicyStore store;
  private final GroupResolver groupResolver;
  private final LocalResourceParser parser = new LocalResourceParser();
  private final Path uploadRoot;

  /** @param uploadRoot canonicalized Kyuubi shared upload root */
  public LocalFileAclEngine(
      PolicedKeys policedKeys,
      PolicyStore store,
      GroupResolver groupResolver,
      Path uploadRoot) {
    this.policedKeys = policedKeys;
    this.store = store;
    this.groupResolver = groupResolver;
    this.uploadRoot = uploadRoot;
  }

  public void validate(String user, Map<String, String> sessionConf) {
    store.maybeReload();
    // One snapshot for the whole submission so every resource is judged by the same policy.
    AclState state = store.current();
    Optional<Path> batchUploadDir = currentBatchUploadDir(sessionConf);
    GroupLookup groups = new GroupLookup(user);
    for (Map.Entry<String, String> entry : sessionConf.entrySet()) {
      Optional<PolicedKey> policedKey = policedKeys.lookup(entry.getKey());
      if (policedKey.isEmpty()) {
        continue;
      }
      List<LocalResource> locals;
      try {
        locals = parser.parse(policedKey.get(), entry.getValue());
      } catch (IllegalArgumentException e) {
        throw deny(user, entry.getKey(), entry.getValue(), e.getMessage());
      }
      for (LocalResource local : locals) {
        authorize(user, entry.getKey(), local, state, batchUploadDir, groups);
      }
    }
  }

  private void authorize(
      String user,
      String key,
      LocalResource local,
      AclState state,
      Optional<Path> batchUploadDir,
      GroupLookup groups) {
    Path path = local.realPath();

    if (path.startsWith(uploadRoot)) {
      if (batchUploadDir.isPresent() && path.startsWith(batchUploadDir.get())) {
        LOG.info("Local file access granted: user={}, key={}, path={}, reason=upload-exemption, "
            + "batchUploadDir={}", user, key, path, batchUploadDir.get());
        return;
      }
      // Unconditional cross-batch isolation: never fall through to username or group rules.
      throw deny(user, key, path.toString(),
          "path is under the Kyuubi upload root but not part of the current batch upload");
    }

    if (!(state instanceof AclState.Valid valid)) {
      String error = state instanceof AclState.Invalid invalid ? invalid.error() : "unknown";
      throw deny(user, key, path.toString(), "the local file ACL state is invalid: " + error);
    }

    for (CompiledRule rule : valid.policy().rulesForUser(user)) {
      if (rule.matches(path)) {
        LOG.debug("Matched user rule '{}' for user {}", rule.patternText(), user);
        LOG.info("Local file access granted: user={}, groups={}, key={}, path={}, "
            + "reason=user-rule, principal={}, pattern={}",
            user, groups.resolvedOrPlaceholder(), key, path, user, rule.patternText());
        return;
      }
    }

    Set<String> resolvedGroups;
    try {
      resolvedGroups = groups.resolve(groupResolver);
    } catch (Exception e) {
      LOG.warn("Hadoop group resolution failed for user {}", user, e);
      throw deny(user, key, path.toString(), "Hadoop group resolution failed");
    }
    for (String group : resolvedGroups) {
      for (CompiledRule rule : valid.policy().rulesForGroup(group)) {
        if (rule.matches(path)) {
          LOG.debug("Matched group rule '{}' via group {} for user {}",
              rule.patternText(), group, user);
          LOG.info("Local file access granted: user={}, groups={}, key={}, path={}, "
              + "reason=group-rule, principal={}, pattern={}",
              user, resolvedGroups, key, path, group, rule.patternText());
          return;
        }
      }
    }
    throw deny(user, key, path.toString(), "no ACL rule authorizes this path (groups="
        + groups.resolvedOrPlaceholder() + ")");
  }

  /**
   * The upload exemption applies only when Kyuubi's reserved upload flag is set and the batch id
   * is a well-formed UUID whose upload directory exists. Interactive clients must be prevented
   * from forging both keys via {@code kyuubi.session.conf.ignore.list} (not the restrict list:
   * Kyuubi injects these keys into every REST batch conf, and {@code AbstractSession} eagerly
   * validates batch conf against the restrict list, so restricting them fails all batches).
   */
  private Optional<Path> currentBatchUploadDir(Map<String, String> sessionConf) {
    if (!Boolean.parseBoolean(sessionConf.get(BATCH_RESOURCE_UPLOADED_KEY))) {
      return Optional.empty();
    }
    String batchId = sessionConf.get(BATCH_ID_KEY);
    if (batchId == null) {
      return Optional.empty();
    }
    try {
      UUID.fromString(batchId);
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
    try {
      return Optional.of(uploadRoot.resolve(batchId).toRealPath());
    } catch (IOException e) {
      return Optional.empty();
    }
  }

  private RuntimeException deny(String user, String key, String resource, String reason) {
    LOG.warn("Local file access denied: user={}, key={}, resource={}, reason={}",
        user, key, resource, reason);
    return sneakyThrow(new KyuubiException("Local file access denied for user '" + user
        + "': configuration key '" + key + "', resource '" + resource + "': " + reason, null));
  }

  /**
   * {@link KyuubiException} is checked but {@code getConfOverlay} declares no throws clause;
   * Kyuubi's Scala call sites are oblivious to Java checked-exception rules.
   */
  @SuppressWarnings("unchecked")
  private static <T extends Throwable> RuntimeException sneakyThrow(Throwable t) throws T {
    throw (T) t;
  }

  /** Resolves groups at most once per validation and remembers the outcome for audit lines. */
  private static final class GroupLookup {
    private final String user;
    private Set<String> groups;

    GroupLookup(String user) {
      this.user = user;
    }

    Set<String> resolve(GroupResolver resolver) throws Exception {
      if (groups == null) {
        groups = resolver.resolveGroups(user);
        LOG.debug("Resolved groups for user {}: {}", user, groups);
      }
      return groups;
    }

    String resolvedOrPlaceholder() {
      return groups == null ? "<unresolved>" : groups.toString();
    }
  }
}
