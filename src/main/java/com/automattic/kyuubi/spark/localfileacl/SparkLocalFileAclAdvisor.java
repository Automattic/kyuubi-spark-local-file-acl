package com.automattic.kyuubi.spark.localfileacl;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Collections;
import java.util.Map;

import org.apache.kyuubi.plugin.SessionConfAdvisor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Kyuubi {@link SessionConfAdvisor} that rejects unauthorized Kyuubi-server-local files supplied
 * through Spark file-distribution configuration, before Kyuubi launches {@code spark-submit}.
 *
 * <p>Configure with {@code kyuubi.session.conf.advisor=com.automattic.kyuubi.spark.localfileacl
 * .SparkLocalFileAclAdvisor} and pass plugin settings as JVM system properties (see
 * {@link PluginSettings}).
 */
public final class SparkLocalFileAclAdvisor implements SessionConfAdvisor {

  private static final Logger LOG = LoggerFactory.getLogger(SparkLocalFileAclAdvisor.class);

  private final LocalFileAclEngine engine;

  public SparkLocalFileAclAdvisor() {
    try {
      PluginSettings settings = PluginSettings.fromSystemProperties();
      PolicedKeys policedKeys =
          PolicedKeys.fromSettings(settings.extraKeysSpec(), settings.excludedKeysSpec());
      Path uploadRoot = canonicalUploadRoot(settings.uploadRoot());
      PolicyStore store = new PolicyStore(
          settings.rulesFile(),
          new AclYamlLoader(uploadRoot, settings.expectedOwner()),
          settings.reloadInterval(),
          Clock.systemUTC(),
          System::nanoTime);
      store.initialLoad();
      this.engine =
          new LocalFileAclEngine(policedKeys, store, new HadoopGroupResolver(), uploadRoot);
      policedKeys.effectiveKeys().forEach((key, policedKey) ->
          LOG.info("Policing local file key {} ({})", key, policedKey.cardinality()));
      LOG.info("SparkLocalFileAclAdvisor initialized: rulesFile={}, reloadInterval={}, "
          + "uploadRoot={}", settings.rulesFile(), settings.reloadInterval(), uploadRoot);
    } catch (Exception e) {
      LOG.error("SparkLocalFileAclAdvisor initialization failed", e);
      throw e instanceof RuntimeException runtime ? runtime : new IllegalStateException(e);
    }
  }

  @Override
  public Map<String, String> getConfOverlay(String user, Map<String, String> sessionConf) {
    engine.validate(user, sessionConf);
    return Collections.emptyMap();
  }

  /**
   * The upload root must canonicalize successfully or cross-batch isolation could be bypassed:
   * a symlinked ancestor would give submitted resources (always {@code toRealPath()}-resolved) a
   * different prefix than a lexically-normalized root, so upload paths would fall through to
   * ordinary ACL rules. Create it if Kyuubi has not yet, and fail startup otherwise.
   */
  private static Path canonicalUploadRoot(Path uploadRoot) {
    try {
      Files.createDirectories(uploadRoot);
      return uploadRoot.toRealPath();
    } catch (IOException e) {
      throw new IllegalStateException("Cannot create or canonicalize the Kyuubi upload root "
          + uploadRoot, e);
    }
  }
}
