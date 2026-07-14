package com.automattic.kyuubi.spark.localfileacl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class PolicedKeysSpec {

  @Test
  void normalizesKeysLikeConvertConfigKey() {
    assertEquals("spark.files", PolicedKeys.normalizeKey("spark.files"));
    assertEquals("spark.files", PolicedKeys.normalizeKey("files"));
    assertEquals("spark.yarn.dist.files", PolicedKeys.normalizeKey("yarn.dist.files"));
    // Kyuubi prepends the prefix to the complete key, keeping the leading "hadoop.".
    assertEquals("spark.hadoop.hadoop.fs.defaultFS",
        PolicedKeys.normalizeKey("hadoop.fs.defaultFS"));
  }

  @Test
  void policesQualifiedAndUnqualifiedAliases() {
    PolicedKeys keys = PolicedKeys.fromSettings(null, null);
    assertTrue(keys.lookup("spark.files").isPresent());
    assertTrue(keys.lookup("files").isPresent());
    assertTrue(keys.lookup("jars").isPresent());
    assertTrue(keys.lookup("yarn.dist.files").isPresent());
    assertTrue(keys.lookup("submit.pyFiles").isPresent());
    assertTrue(keys.lookup("kerberos.keytab").isPresent());
    assertEquals(Cardinality.SCALAR, keys.lookup("spark.yarn.keytab").orElseThrow());
    assertEquals(Cardinality.LIST, keys.lookup("spark.archives").orElseThrow());
  }

  @Test
  void doesNotPoliceSimilarOrUploadPathKeys() {
    PolicedKeys keys = PolicedKeys.fromSettings(null, null);
    assertFalse(keys.lookup("spark.kubernetes.file.upload.path").isPresent());
    assertFalse(keys.lookup("spark.files.something").isPresent());
    assertFalse(keys.lookup("spark.filesXyz").isPresent());
    assertFalse(keys.lookup("myfiles").isPresent());
    assertFalse(keys.lookup("spark.jars.packages").isPresent());
    assertFalse(keys.lookup("spark.jars.ivy").isPresent());
  }

  @Test
  void addsExtraKeysWithDeclaredCardinality() {
    PolicedKeys keys =
        PolicedKeys.fromSettings("spark.custom.files:list, custom.keytab:scalar", null);
    assertEquals(Cardinality.LIST, keys.lookup("spark.custom.files").orElseThrow());
    assertEquals(Cardinality.SCALAR, keys.lookup("custom.keytab").orElseThrow());
    assertEquals(Cardinality.SCALAR, keys.lookup("spark.custom.keytab").orElseThrow());
  }

  @Test
  void excludedKeysTakePrecedenceOverDefaultsAndExtras() {
    PolicedKeys keys = PolicedKeys.fromSettings(
        "spark.custom.files:list", "spark.yarn.keytab,spark.custom.files");
    assertFalse(keys.lookup("spark.yarn.keytab").isPresent());
    assertFalse(keys.lookup("yarn.keytab").isPresent());
    assertFalse(keys.lookup("spark.custom.files").isPresent());
    assertTrue(keys.lookup("spark.kerberos.keytab").isPresent());
  }

  @Test
  void normalizesEscapeHatchKeysBeforeMatching() {
    PolicedKeys keys = PolicedKeys.fromSettings(null, "yarn.keytab");
    assertFalse(keys.lookup("spark.yarn.keytab").isPresent());
  }

  @Test
  void rejectsMalformedEscapeHatchEntries() {
    assertThrows(IllegalArgumentException.class,
        () -> PolicedKeys.fromSettings("spark.custom.files", null));
    assertThrows(IllegalArgumentException.class,
        () -> PolicedKeys.fromSettings("spark.custom.files:", null));
    assertThrows(IllegalArgumentException.class,
        () -> PolicedKeys.fromSettings(":list", null));
    assertThrows(IllegalArgumentException.class,
        () -> PolicedKeys.fromSettings("spark.custom.files:map", null));
    assertThrows(IllegalArgumentException.class,
        () -> PolicedKeys.fromSettings("a:list,,b:list", null));
  }

  @Test
  void rejectsConflictingAndDuplicateDefinitions() {
    // Conflicts with the default LIST cardinality of spark.files.
    assertThrows(IllegalArgumentException.class,
        () -> PolicedKeys.fromSettings("files:scalar", null));
    // Duplicate extra definitions, even via alias normalization.
    assertThrows(IllegalArgumentException.class,
        () -> PolicedKeys.fromSettings("spark.custom.files:list,custom.files:list", null));
  }

  @Test
  void rejectsExclusionsWithoutMatchingKey() {
    assertThrows(IllegalArgumentException.class,
        () -> PolicedKeys.fromSettings(null, "spark.nonexistent.key"));
  }
}
