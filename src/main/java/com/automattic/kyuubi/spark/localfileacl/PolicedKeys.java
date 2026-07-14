package com.automattic.kyuubi.spark.localfileacl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The effective set of policed Spark configuration keys and their cardinalities:
 * {@code (defaults ∪ extra keys) - excluded keys}, all normalized with the same rules Kyuubi's
 * {@code SparkProcessBuilder.convertConfigKey} applies when assembling the spark-submit command.
 */
public final class PolicedKeys {

  private static final Map<String, Cardinality> DEFAULTS = createDefaults();

  private static Map<String, Cardinality> createDefaults() {
    Map<String, Cardinality> defaults = new LinkedHashMap<>();
    defaults.put("spark.files", Cardinality.LIST);
    defaults.put("spark.jars", Cardinality.LIST);
    defaults.put("spark.archives", Cardinality.LIST);
    defaults.put("spark.yarn.jars", Cardinality.LIST);
    defaults.put("spark.yarn.dist.files", Cardinality.LIST);
    defaults.put("spark.yarn.dist.pyFiles", Cardinality.LIST);
    defaults.put("spark.submit.pyFiles", Cardinality.LIST);
    defaults.put("spark.yarn.dist.jars", Cardinality.LIST);
    defaults.put("spark.yarn.dist.archives", Cardinality.LIST);
    defaults.put("spark.kerberos.keytab", Cardinality.SCALAR);
    defaults.put("spark.yarn.keytab", Cardinality.SCALAR);
    defaults.put("spark.kubernetes.kerberos.krb5.path", Cardinality.SCALAR);
    return Collections.unmodifiableMap(defaults);
  }

  private final Map<String, Cardinality> bySparkKey;

  private PolicedKeys(Map<String, Cardinality> bySparkKey) {
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
    Map<String, Cardinality> effective = new LinkedHashMap<>(DEFAULTS);

    parseExtraKeys(extraKeysSpec).forEach((key, cardinality) -> {
      Cardinality existing = effective.get(key);
      if (existing != null && existing != cardinality) {
        throw new IllegalArgumentException("Conflicting definitions for policed key '" + key
            + "': " + existing + " vs " + cardinality);
      }
      effective.put(key, cardinality);
    });

    for (String excluded : splitSpec(excludedKeysSpec)) {
      String normalized = normalizeKey(excluded);
      if (effective.remove(normalized) == null) {
        throw new IllegalArgumentException("Excluded key '" + excluded + "' (normalized '"
            + normalized + "') does not match any default or extra policed key");
      }
    }
    return new PolicedKeys(effective);
  }

  private static Map<String, Cardinality> parseExtraKeys(String extraKeysSpec) {
    Map<String, Cardinality> extras = new LinkedHashMap<>();
    for (String entry : splitSpec(extraKeysSpec)) {
      String[] parts = entry.split(":", -1);
      if (parts.length != 2 || parts[0].isBlank() || parts[1].isBlank()) {
        throw new IllegalArgumentException("Malformed extra key entry '" + entry
            + "'; expected '<key>:list' or '<key>:scalar'");
      }
      String normalized = normalizeKey(parts[0].strip());
      if (extras.containsKey(normalized)) {
        throw new IllegalArgumentException("Duplicate extra key definition for '" + normalized + "'");
      }
      extras.put(normalized, Cardinality.parse(parts[1]));
    }
    return extras;
  }

  private static List<String> splitSpec(String spec) {
    if (spec == null || spec.isBlank()) {
      return List.of();
    }
    List<String> entries = new ArrayList<>();
    for (String entry : spec.split(",", -1)) {
      String stripped = entry.strip();
      if (stripped.isEmpty()) {
        throw new IllegalArgumentException("Empty entry in key spec '" + spec + "'");
      }
      entries.add(stripped);
    }
    return entries;
  }

  /** Looks up a session configuration key after normalization; exact matches only. */
  public Optional<Cardinality> lookup(String sessionConfKey) {
    return Optional.ofNullable(bySparkKey.get(normalizeKey(sessionConfKey)));
  }

  public Map<String, Cardinality> effectiveKeys() {
    return bySparkKey;
  }
}
