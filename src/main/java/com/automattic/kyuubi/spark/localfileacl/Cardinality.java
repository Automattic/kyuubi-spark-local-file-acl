package com.automattic.kyuubi.spark.localfileacl;

import java.util.Locale;

/** How a policed Spark configuration value is parsed: a comma-separated list or one resource. */
public enum Cardinality {
  LIST,
  SCALAR;

  static Cardinality parse(String value) {
    return switch (value.strip().toLowerCase(Locale.ROOT)) {
      case "list" -> LIST;
      case "scalar" -> SCALAR;
      default ->
          throw new IllegalArgumentException(
              "Unknown cardinality '" + value + "'; expected 'list' or 'scalar'");
    };
  }
}
