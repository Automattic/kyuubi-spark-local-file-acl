package com.automattic.kyuubi.spark.localfileacl;

import java.nio.file.Path;
import java.time.Duration;

/**
 * Plugin-only settings read from JVM system properties set in {@code kyuubi-env.sh}, so they can
 * never enter session configuration or the generated Spark configuration.
 */
public record PluginSettings(
    Path rulesFile,
    Duration reloadInterval,
    String extraKeysSpec,
    String excludedKeysSpec,
    Path uploadRoot,
    String expectedOwner,
    boolean wildcardsEnabled,
    boolean failOnMissingFiles) {

  public static final String RULES_FILE_PROP = "kyuubi.local.file.acl.rules.file";
  public static final String RELOAD_INTERVAL_PROP = "kyuubi.local.file.acl.reload.interval";
  public static final String EXTRA_KEYS_PROP = "kyuubi.local.file.acl.extra.keys";
  public static final String EXCLUDED_KEYS_PROP = "kyuubi.local.file.acl.excluded.keys";
  public static final String UPLOAD_ROOT_PROP = "kyuubi.local.file.acl.upload.root";
  public static final String EXPECTED_OWNER_PROP = "kyuubi.local.file.acl.expected.owner";
  public static final String WILDCARDS_ENABLED_PROP = "kyuubi.local.file.acl.wildcards.enabled";
  public static final String FAIL_ON_MISSING_FILES_PROP =
      "kyuubi.local.file.acl.fail.on.missing.files";

  public static final String DEFAULT_RULES_FILE_NAME = "kyuubi-local-file-acl.yaml";

  public PluginSettings {
    if (reloadInterval.isNegative() || reloadInterval.isZero()) {
      throw new IllegalArgumentException("Reload interval must be positive: " + reloadInterval);
    }
  }

  public static PluginSettings fromSystemProperties() {
    Path rulesFile = resolveRulesFile();
    Duration reloadInterval = Duration.parse(System.getProperty(RELOAD_INTERVAL_PROP, "PT60S"));
    Path uploadRoot = resolveUploadRoot();
    String expectedOwner = System.getProperty(EXPECTED_OWNER_PROP);
    return new PluginSettings(
        rulesFile,
        reloadInterval,
        System.getProperty(EXTRA_KEYS_PROP),
        System.getProperty(EXCLUDED_KEYS_PROP),
        uploadRoot,
        expectedOwner == null || expectedOwner.isBlank() ? null : expectedOwner.strip(),
        booleanProperty(WILDCARDS_ENABLED_PROP, false),
        booleanProperty(FAIL_ON_MISSING_FILES_PROP, true));
  }

  /**
   * Only {@code true} and {@code false} are accepted, for every boolean setting. {@code
   * Boolean.parseBoolean} would map a typo to {@code false}, which for {@link
   * #FAIL_ON_MISSING_FILES_PROP} silently turns off the fail-closed treatment of exact rules whose
   * file does not exist — a mode a security-sensitive flag must never select by accident.
   */
  private static boolean booleanProperty(String property, boolean defaultValue) {
    String configured = System.getProperty(property);
    if (configured == null) {
      return defaultValue;
    }
    String value = configured.strip();
    if ("true".equalsIgnoreCase(value)) {
      return true;
    }
    if ("false".equalsIgnoreCase(value)) {
      return false;
    }
    throw new IllegalArgumentException(
        "Property " + property + " must be 'true' or 'false' but was '" + configured + "'");
  }

  private static Path resolveRulesFile() {
    String configured = System.getProperty(RULES_FILE_PROP);
    if (configured != null && !configured.isBlank()) {
      return Path.of(configured);
    }
    String confDir = System.getenv("KYUUBI_CONF_DIR");
    if (confDir != null && !confDir.isBlank()) {
      return Path.of(confDir, DEFAULT_RULES_FILE_NAME);
    }
    throw new IllegalArgumentException(
        "ACL rules file location is not configured; set -D"
            + RULES_FILE_PROP
            + " or the KYUUBI_CONF_DIR environment variable");
  }

  /**
   * Mirrors Kyuubi's {@code KyuubiApplicationManager.uploadWorkDir} resolution: {@code
   * $KYUUBI_WORK_DIR_ROOT/upload}, falling back to {@code ${user.dir}/upload}.
   */
  private static Path resolveUploadRoot() {
    String configured = System.getProperty(UPLOAD_ROOT_PROP);
    if (configured != null && !configured.isBlank()) {
      return Path.of(configured);
    }
    String workDirRoot = System.getenv("KYUUBI_WORK_DIR_ROOT");
    if (workDirRoot != null && !workDirRoot.isBlank()) {
      return Path.of(workDirRoot, "upload");
    }
    return Path.of(System.getProperty("user.dir"), "upload");
  }
}
