package com.automattic.kyuubi.spark.localfileacl;

import java.nio.file.Path;
import java.nio.file.PathMatcher;

/** A single compiled allow rule, matched against canonical local paths. */
public sealed interface CompiledRule permits CompiledRule.Glob, CompiledRule.Exact {

  String patternText();

  boolean matches(Path canonicalPath);

  record Glob(String patternText, PathMatcher matcher) implements CompiledRule {
    @Override
    public boolean matches(Path canonicalPath) {
      return matcher.matches(canonicalPath);
    }
  }

  record Exact(String patternText, Path canonicalPath) implements CompiledRule {
    @Override
    public boolean matches(Path path) {
      return canonicalPath.equals(path);
    }
  }
}
