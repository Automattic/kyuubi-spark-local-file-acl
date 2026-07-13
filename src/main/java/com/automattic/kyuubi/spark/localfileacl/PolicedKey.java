package com.automattic.kyuubi.spark.localfileacl;

/** A Spark configuration key whose value supplies local input files to the engine. */
public record PolicedKey(String sparkKey, Cardinality cardinality) {

  public enum Cardinality {
    LIST,
    SCALAR;

    static Cardinality parse(String value) {
      return switch (value.trim().toLowerCase(java.util.Locale.ROOT)) {
        case "list" -> LIST;
        case "scalar" -> SCALAR;
        default -> throw new IllegalArgumentException("Unknown cardinality '" + value
            + "'; expected 'list' or 'scalar'");
      };
    }
  }
}
