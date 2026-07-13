package com.automattic.kyuubi.spark.localfileacl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.automattic.kyuubi.spark.localfileacl.PolicedKey.Cardinality;

/**
 * The effective set of policed Spark configuration keys:
 * {@code (defaults ∪ extra keys) - excluded keys}, all normalized with the same rules Kyuubi's
 * {@code SparkProcessBuilder.convertConfigKey} applies when assembling the spark-submit command.
 */
public final class PolicedKeys {

  private static final List<PolicedKey> DEFAULTS = List.of(
      new PolicedKey("spark.files", Cardinality.LIST),
      new PolicedKey("spark.jars", Cardinality.LIST),
      new PolicedKey("spark.archives", Cardinality.LIST),
      new PolicedKey("spark.yarn.jars", Cardinality.LIST),
      new PolicedKey("spark.yarn.dist.files", Cardinality.LIST),
      new PolicedKey("spark.yarn.dist.pyFiles", Cardinality.LIST),
      new PolicedKey("spark.submit.pyFiles", Cardinality.LIST),
      new PolicedKey("spark.yarn.dist.jars", Cardinality.LIST),
      new PolicedKey("spark.yarn.dist.archives", Cardinality.LIST),
      new PolicedKey("spark.kerberos.keytab", Cardinality.SCALAR),
      new PolicedKey("spark.yarn.keytab", Cardinality.SCALAR),
      new PolicedKey("spark.kubernetes.kerberos.krb5.path", Cardinality.SCALAR));

  private final Map<String, PolicedKey> bySparkKey;

  private PolicedKeys(Map<String, PolicedKey> bySparkKey) {
    this.bySparkKey = Collections.unmodifiableMap(bySparkKey);
  }

  /**
   * Equivalent of Kyuubi's {@code SparkProcessBuilder.convertConfigKey}: {@code spark.*} keys are
   * kept as-is, {@code hadoop.*} keys are prefixed with {@code spark.hadoop.}, everything else is
   * prefixed with {@code spark.}.
   */
  public static String normalizeKey(String key) {
    if (key.startsWith("spark.")) {
      return key;
    }
    if (key.startsWith("hadoop.")) {
      return "spark.hadoop." + key;
    }
    return "spark." + key;
  }

  public static PolicedKeys fromSettings(String extraKeysSpec, String excludedKeysSpec) {
    Map<String, PolicedKey> effective = new LinkedHashMap<>();
    DEFAULTS.forEach(key -> effective.put(key.sparkKey(), key));

    for (PolicedKey extra : parseExtraKeys(extraKeysSpec)) {
      PolicedKey existing = effective.get(extra.sparkKey());
      if (existing != null && existing.cardinality() != extra.cardinality()) {
        throw new IllegalArgumentException("Conflicting definitions for policed key '"
            + extra.sparkKey() + "': " + existing.cardinality() + " vs " + extra.cardinality());
      }
      effective.put(extra.sparkKey(), extra);
    }

    for (String excluded : splitSpec(excludedKeysSpec)) {
      String normalized = normalizeKey(excluded);
      if (effective.remove(normalized) == null) {
        throw new IllegalArgumentException("Excluded key '" + excluded + "' (normalized '"
            + normalized + "') does not match any default or extra policed key");
      }
    }
    return new PolicedKeys(effective);
  }

  private static List<PolicedKey> parseExtraKeys(String extraKeysSpec) {
    List<PolicedKey> extras = new ArrayList<>();
    List<String> seen = new ArrayList<>();
    for (String entry : splitSpec(extraKeysSpec)) {
      String[] parts = entry.split(":", -1);
      if (parts.length != 2 || parts[0].isBlank() || parts[1].isBlank()) {
        throw new IllegalArgumentException("Malformed extra key entry '" + entry
            + "'; expected '<key>:list' or '<key>:scalar'");
      }
      String normalized = normalizeKey(parts[0].trim());
      if (seen.contains(normalized)) {
        throw new IllegalArgumentException("Duplicate extra key definition for '" + normalized + "'");
      }
      seen.add(normalized);
      extras.add(new PolicedKey(normalized, Cardinality.parse(parts[1])));
    }
    return extras;
  }

  private static List<String> splitSpec(String spec) {
    if (spec == null || spec.isBlank()) {
      return List.of();
    }
    List<String> entries = new ArrayList<>();
    for (String entry : spec.split(",", -1)) {
      String trimmed = entry.trim();
      if (trimmed.isEmpty()) {
        throw new IllegalArgumentException("Empty entry in key spec '" + spec + "'");
      }
      entries.add(trimmed);
    }
    return entries;
  }

  /** Looks up a session configuration key after normalization; exact matches only. */
  public Optional<PolicedKey> lookup(String sessionConfKey) {
    return Optional.ofNullable(bySparkKey.get(normalizeKey(sessionConfKey)));
  }

  public Map<String, PolicedKey> effectiveKeys() {
    return bySparkKey;
  }
}
