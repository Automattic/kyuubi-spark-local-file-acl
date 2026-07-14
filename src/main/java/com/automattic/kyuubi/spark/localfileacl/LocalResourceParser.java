package com.automattic.kyuubi.spark.localfileacl;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Extracts the Kyuubi-server-local resources from a policed configuration value as canonical
 * paths. Remote URIs (hdfs, s3, http, ...) are ignored; malformed or non-concrete local entries
 * are rejected with {@link IllegalArgumentException}.
 */
public final class LocalResourceParser {

  public List<Path> parse(Cardinality cardinality, String rawValue) {
    List<String> entries = switch (cardinality) {
      case LIST -> List.of(rawValue.split(",", -1));
      case SCALAR -> List.of(rawValue);
    };
    List<Path> locals = new ArrayList<>();
    for (String entry : entries) {
      // ASCII-only trim(), NOT strip(): Spark trims at most ASCII whitespace from resource
      // values, so validating a Unicode-stripped variant would authorize a different file
      // than Spark resolves. Unicode-whitespace-suffixed values then fail URI parsing and
      // are rejected rather than silently rewritten.
      String trimmed = entry.trim();
      if (trimmed.isEmpty()) {
        throw new IllegalArgumentException("Empty resource entry");
      }
      parseEntry(trimmed).ifPresent(locals::add);
    }
    return locals;
  }

  private Optional<Path> parseEntry(String entry) {
    URI uri;
    try {
      uri = new URI(entry);
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("Malformed resource URI '" + entry + "': "
          + e.getMessage(), e);
    }
    String scheme = uri.getScheme();
    if (scheme != null && !scheme.equalsIgnoreCase("file")) {
      return Optional.empty();
    }
    String authority = uri.getAuthority();
    if (authority != null && !authority.isEmpty()) {
      throw new IllegalArgumentException("Local resource '" + entry
          + "' must not carry a URI authority");
    }
    if (uri.getQuery() != null) {
      // Spark receives the original URI; authorizing only the path while a query is present
      // would leave the effective resource ambiguous.
      throw new IllegalArgumentException("Local resource '" + entry
          + "' must not carry a URI query");
    }
    // uri.getPath() already excludes any '#alias' fragment.
    String path = uri.getPath();
    if (path == null || path.isEmpty() || !path.startsWith("/")) {
      throw new IllegalArgumentException("Local resource '" + entry + "' must be an absolute path");
    }
    if (AclYamlLoader.containsGlobMeta(path)) {
      throw new IllegalArgumentException("Local resource '" + entry
          + "' must identify a concrete file, not a glob");
    }
    Path realPath;
    try {
      realPath = Path.of(path).toRealPath();
    } catch (IOException e) {
      throw new IllegalArgumentException("Local resource '" + entry
          + "' does not exist or cannot be resolved: " + e.getMessage(), e);
    }
    if (!Files.isRegularFile(realPath)) {
      throw new IllegalArgumentException("Local resource '" + entry + "' is not a regular file");
    }
    return Optional.of(realPath);
  }
}
