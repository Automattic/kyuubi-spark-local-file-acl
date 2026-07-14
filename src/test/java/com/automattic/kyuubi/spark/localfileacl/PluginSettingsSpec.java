package com.automattic.kyuubi.spark.localfileacl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PluginSettingsSpec {

  @TempDir Path tempDir;

  @BeforeEach
  void setUp() {
    System.setProperty(PluginSettings.RULES_FILE_PROP, tempDir.resolve("acl.yaml").toString());
  }

  @AfterEach
  void clearProperties() {
    System.clearProperty(PluginSettings.RULES_FILE_PROP);
    System.clearProperty(PluginSettings.WILDCARDS_ENABLED_PROP);
    System.clearProperty(PluginSettings.FAIL_ON_MISSING_FILES_PROP);
  }

  @Test
  void defaultsDisableWildcardsAndFailOnMissingFiles() {
    PluginSettings settings = PluginSettings.fromSystemProperties();
    assertFalse(settings.wildcardsEnabled());
    assertTrue(settings.failOnMissingFiles());
  }

  @Test
  void readsExplicitValuesCaseInsensitively() {
    System.setProperty(PluginSettings.WILDCARDS_ENABLED_PROP, "TRUE");
    System.setProperty(PluginSettings.FAIL_ON_MISSING_FILES_PROP, " False ");
    PluginSettings settings = PluginSettings.fromSystemProperties();
    assertTrue(settings.wildcardsEnabled());
    assertFalse(settings.failOnMissingFiles());
  }

  @Test
  void rejectsBlankAndUnrecognizedBooleans() {
    // Boolean.parseBoolean would read every one of these as 'false', silently turning off the
    // fail-closed handling of exact rules whose file does not exist.
    for (String value : List.of("", "   ", "yes", "1", "off", "tru")) {
      System.setProperty(PluginSettings.FAIL_ON_MISSING_FILES_PROP, value);
      IllegalArgumentException e =
          assertThrows(IllegalArgumentException.class, PluginSettings::fromSystemProperties);
      assertTrue(
          e.getMessage().contains(PluginSettings.FAIL_ON_MISSING_FILES_PROP), e.getMessage());
    }
    System.clearProperty(PluginSettings.FAIL_ON_MISSING_FILES_PROP);

    System.setProperty(PluginSettings.WILDCARDS_ENABLED_PROP, "enabled");
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, PluginSettings::fromSystemProperties);
    assertEquals(
        "Property "
            + PluginSettings.WILDCARDS_ENABLED_PROP
            + " must be 'true' or 'false' but was 'enabled'",
        e.getMessage());
  }
}
