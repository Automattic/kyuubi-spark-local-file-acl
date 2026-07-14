package com.automattic.kyuubi.spark.localfileacl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/**
 * Parses and validates the YAML ACL policy into an immutable {@link AclPolicy}. Any violation
 * throws {@link IllegalArgumentException}; the caller never observes a partially compiled policy.
 */
public final class AclYamlLoader {

  private static final Logger LOG = LoggerFactory.getLogger(AclYamlLoader.class);

  private static final int SUPPORTED_VERSION = 1;
  private static final String GLOB_META_CHARS = "*?[]{}";
  private static final Set<String> TOP_LEVEL_KEYS = Set.of("version", "users", "groups");

  /** Hard cap applied before the content is read; a policy file has no business being larger. */
  static final long MAX_ACL_BYTES = 1 << 20;

  private static final int READ_RETRIES = 3;

  /**
   * @param uploadRoot canonicalized Kyuubi shared upload root
   * @param expectedOwner required owner of the ACL file and its ancestor directories, or null to
   *     skip the ownership checks
   * @param wildcardsEnabled whether glob patterns may appear in {@code allow} entries
   * @param failOnMissingFiles whether an exact rule naming a nonexistent file invalidates the
   *     policy; when false the rule is logged at ERROR and omitted
   */
  public record Options(
      Path uploadRoot,
      String expectedOwner,
      boolean wildcardsEnabled,
      boolean failOnMissingFiles) {}

  private final Options options;

  /** Test seam: runs between the pre-read integrity check and the content read. */
  private final Runnable preReadHook;

  /** Test seam: resolves the owning OS user of a path. */
  private final Function<Path, String> ownerLookup;

  public AclYamlLoader(Options options) {
    this(options, null, AclYamlLoader::systemOwner);
  }

  AclYamlLoader(Options options, Runnable preReadHook) {
    this(options, preReadHook, AclYamlLoader::systemOwner);
  }

  AclYamlLoader(Options options, Runnable preReadHook, Function<Path, String> ownerLookup) {
    this.options = options;
    this.preReadHook = preReadHook;
    this.ownerLookup = ownerLookup;
  }

  private static String systemOwner(Path path) {
    try {
      return Files.getOwner(path, LinkOption.NOFOLLOW_LINKS).getName();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /**
   * Verifies the ACL file's integrity and reads its content as one consistent, bounded snapshot.
   * The file must be regular, within the size cap, not beneath the Kyuubi upload root, and owned by
   * the expected owner when one is configured; neither it nor any ancestor directory may be group-
   * or world-writable, and with a configured owner every ancestor directory must be owned by that
   * owner or root (otherwise a directory-entry swap could substitute the policy). The read itself
   * is bounded to the cap and accepted only when the file key, size, and modification time are
   * identical before and after, the content length matches, and a second full integrity check
   * passes — guarding against a swap or rewrite between validation and read.
   */
  public byte[] readVerified(Path aclFile) throws IOException {
    IOException unstable = null;
    for (int attempt = 0; attempt < READ_RETRIES; attempt++) {
      Path realFile;
      try {
        realFile = aclFile.toRealPath();
      } catch (IOException e) {
        throw new IOException("ACL file is missing or unresolvable: " + aclFile, e);
      }
      BasicFileAttributes before =
          Files.readAttributes(realFile, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      verifyIntegrity(realFile, before);
      if (preReadHook != null) {
        preReadHook.run();
      }
      byte[] content;
      try (var in = Files.newInputStream(realFile)) {
        content = in.readNBytes((int) MAX_ACL_BYTES + 1);
      }
      if (content.length > MAX_ACL_BYTES) {
        throw new IOException("ACL file exceeds the " + MAX_ACL_BYTES + " byte limit: " + realFile);
      }
      BasicFileAttributes after =
          Files.readAttributes(realFile, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      verifyIntegrity(realFile, after);
      if (before.fileKey() != null
          && before.fileKey().equals(after.fileKey())
          && before.size() == after.size()
          && before.lastModifiedTime().equals(after.lastModifiedTime())
          && content.length == before.size()) {
        return content;
      }
      unstable = new IOException("ACL file changed while being read: " + realFile);
    }
    throw unstable;
  }

  private void verifyIntegrity(Path realFile, BasicFileAttributes attributes) throws IOException {
    if (!attributes.isRegularFile()) {
      throw new IOException("ACL file is not a regular file: " + realFile);
    }
    if (attributes.size() > MAX_ACL_BYTES) {
      throw new IOException("ACL file exceeds the " + MAX_ACL_BYTES + " byte limit: " + realFile);
    }
    if (realFile.startsWith(options.uploadRoot())) {
      throw new IOException("ACL file must not live beneath the Kyuubi upload root: " + realFile);
    }
    String expectedOwner = options.expectedOwner();
    if (expectedOwner != null) {
      String owner = ownerLookup.apply(realFile);
      if (!expectedOwner.equals(owner)) {
        throw new IOException(
            "ACL file is owned by '"
                + owner
                + "' but '"
                + expectedOwner
                + "' is required: "
                + realFile);
      }
    }
    rejectLoosePermissions(realFile, "ACL file");
    for (Path dir = realFile.getParent(); dir != null; dir = dir.getParent()) {
      rejectLoosePermissions(dir, "ACL file ancestor directory");
      if (expectedOwner != null) {
        String dirOwner = ownerLookup.apply(dir);
        if (!expectedOwner.equals(dirOwner) && !"root".equals(dirOwner)) {
          throw new IOException(
              "ACL file ancestor directory "
                  + dir
                  + " is owned by '"
                  + dirOwner
                  + "'; only '"
                  + expectedOwner
                  + "' or root may control the path to the policy");
        }
      }
    }
  }

  private static void rejectLoosePermissions(Path path, String what) throws IOException {
    int mode;
    try {
      mode = (int) Files.getAttribute(path, "unix:mode", LinkOption.NOFOLLOW_LINKS);
    } catch (UnsupportedOperationException ignored) {
      // Non-POSIX filesystem; ownership must be enforced by the deployment.
      return;
    }
    boolean groupOrWorldWritable = (mode & 0022) != 0;
    // A sticky directory (like /tmp, mode 1777) restricts rename/delete of entries to their
    // owners, so it does not enable the directory-entry swap this check defends against. The
    // file-type bits come from the same mode snapshot to avoid a second racy stat.
    boolean stickyDirectory = (mode & 01000) != 0 && (mode & 0170000) == 0040000;
    if (groupOrWorldWritable && !stickyDirectory) {
      throw new IOException(what + " must not be group- or world-writable: " + path);
    }
  }

  public AclPolicy parse(byte[] content) {
    LoaderOptions options = new LoaderOptions();
    options.setAllowDuplicateKeys(false);
    Yaml yaml = new Yaml(new SafeConstructor(options));
    Object root = yaml.load(new ByteArrayInputStream(content));
    Map<String, Object> rootMap = asMap(root, "top-level document");

    for (String key : rootMap.keySet()) {
      if (!TOP_LEVEL_KEYS.contains(key)) {
        throw new IllegalArgumentException("Unknown top-level key '" + key + "' in ACL file");
      }
    }
    Object version = rootMap.get("version");
    if (!Integer.valueOf(SUPPORTED_VERSION).equals(version)) {
      throw new IllegalArgumentException(
          "Unsupported ACL version '" + version + "'; expected " + SUPPORTED_VERSION);
    }

    // Exact rules whose file is missing are omitted in lenient mode; the policy carries their
    // paths so PolicyStore can reparse (and canonicalize) once such a file appears.
    Set<Path> unresolved = new LinkedHashSet<>();
    return new AclPolicy(
        parsePrincipals(rootMap.get("users"), "users", unresolved),
        parsePrincipals(rootMap.get("groups"), "groups", unresolved),
        unresolved);
  }

  private Map<String, List<CompiledRule>> parsePrincipals(
      Object section, String sectionName, Set<Path> unresolved) {
    Map<String, List<CompiledRule>> compiled = new LinkedHashMap<>();
    if (section == null) {
      return compiled;
    }
    Map<String, Object> principals = asMap(section, "'" + sectionName + "' section");
    principals.forEach(
        (principal, body) -> {
          if (principal == null || principal.isBlank()) {
            throw new IllegalArgumentException("Blank principal name in '" + sectionName + "'");
          }
          Map<String, Object> entry = asMap(body, sectionName + "." + principal);
          for (String key : entry.keySet()) {
            if (!"allow".equals(key)) {
              throw new IllegalArgumentException(
                  "Unknown key '"
                      + key
                      + "' under "
                      + sectionName
                      + "."
                      + principal
                      + "; only 'allow' is supported");
            }
          }
          compiled.put(
              principal,
              compilePatterns(entry.get("allow"), sectionName + "." + principal, unresolved));
        });
    return compiled;
  }

  private List<CompiledRule> compilePatterns(Object allow, String owner, Set<Path> unresolved) {
    if (allow == null) {
      return List.of();
    }
    if (!(allow instanceof List<?> patterns)) {
      throw new IllegalArgumentException("'allow' under " + owner + " must be a list of patterns");
    }
    List<CompiledRule> rules = new ArrayList<>();
    for (Object patternObject : patterns) {
      if (!(patternObject instanceof String pattern) || pattern.isBlank()) {
        throw new IllegalArgumentException("Non-string or blank pattern under " + owner);
      }
      compilePattern(pattern.strip(), owner, unresolved).ifPresent(rules::add);
    }
    return rules;
  }

  /**
   * Empty when the rule is omitted: a missing exact file while {@code failOnMissingFiles} is off.
   */
  private Optional<CompiledRule> compilePattern(
      String pattern, String owner, Set<Path> unresolved) {
    if (pattern.matches("^[A-Za-z][A-Za-z0-9+.\\-]*:.*")) {
      throw new IllegalArgumentException(
          "Pattern '"
              + pattern
              + "' under "
              + owner
              + " must be an absolute local path, not a URI");
    }
    if (!pattern.startsWith("/")) {
      throw new IllegalArgumentException(
          "Pattern '" + pattern + "' under " + owner + " must be absolute");
    }
    for (String segment : pattern.split("/")) {
      if ("..".equals(segment)) {
        throw new IllegalArgumentException(
            "Pattern '" + pattern + "' under " + owner + " must not contain a '..' segment");
      }
    }
    if (containsGlobMeta(pattern)) {
      if (!options.wildcardsEnabled()) {
        throw new IllegalArgumentException(
            "Pattern '"
                + pattern
                + "' under "
                + owner
                + " uses wildcard matching, which is disabled; set -D"
                + PluginSettings.WILDCARDS_ENABLED_PROP
                + "=true to enable it");
      }
      rejectUploadRootTarget(literalDirPrefix(pattern), pattern, owner);
      PathMatcher matcher;
      try {
        matcher = FileSystems.getDefault().getPathMatcher("glob:" + pattern);
      } catch (RuntimeException e) {
        throw new IllegalArgumentException(
            "Invalid glob pattern '" + pattern + "' under " + owner + ": " + e.getMessage(), e);
      }
      return Optional.of(new CompiledRule.Glob(pattern, matcher));
    }
    Path patternPath = Path.of(pattern);
    Path normalized = patternPath.normalize();
    rejectUploadRootTarget(normalized, pattern, owner);
    Path canonical;
    try {
      canonical = patternPath.toRealPath();
    } catch (NoSuchFileException e) {
      // Only a genuinely absent file is tolerable. Permission failures, symlink loops, and every
      // other I/O error still invalidate the policy, in both modes.
      if (options.failOnMissingFiles()) {
        throw missingExactFile(pattern, owner, e);
      }
      LOG.error(
          "Exact pattern '{}' under {} does not resolve to an existing file; the rule is omitted "
              + "from the active policy and authorizes nothing until the file appears",
          pattern,
          owner);
      unresolved.add(normalized);
      return Optional.empty();
    } catch (IOException e) {
      throw missingExactFile(pattern, owner, e);
    }
    rejectUploadRootTarget(canonical, pattern, owner);
    return Optional.of(new CompiledRule.Exact(pattern, canonical));
  }

  private static IllegalArgumentException missingExactFile(
      String pattern, String owner, IOException cause) {
    return new IllegalArgumentException(
        "Exact pattern '"
            + pattern
            + "' under "
            + owner
            + " does not resolve to an existing file: "
            + cause.getMessage(),
        cause);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> asMap(Object value, String what) {
    if (!(value instanceof Map<?, ?> map)) {
      throw new IllegalArgumentException(
          "Expected a mapping for "
              + what
              + " but found "
              + (value == null ? "nothing" : value.getClass().getSimpleName()));
    }
    map.keySet()
        .forEach(
            key -> {
              if (!(key instanceof String)) {
                throw new IllegalArgumentException("Non-string key '" + key + "' in " + what);
              }
            });
    return (Map<String, Object>) map;
  }

  static boolean containsGlobMeta(String value) {
    for (int i = 0; i < value.length(); i++) {
      if (GLOB_META_CHARS.indexOf(value.charAt(i)) >= 0) {
        return true;
      }
    }
    return false;
  }

  /** The directory part of the pattern before the first glob metacharacter. */
  private static Path literalDirPrefix(String pattern) {
    int firstMeta = pattern.length();
    for (int i = 0; i < pattern.length(); i++) {
      if (GLOB_META_CHARS.indexOf(pattern.charAt(i)) >= 0) {
        firstMeta = i;
        break;
      }
    }
    String literal = pattern.substring(0, firstMeta);
    int lastSlash = literal.lastIndexOf('/');
    Path prefix = Path.of(lastSlash <= 0 ? "/" : literal.substring(0, lastSlash));
    try {
      return prefix.toRealPath();
    } catch (IOException e) {
      return prefix.normalize().toAbsolutePath();
    }
  }

  private void rejectUploadRootTarget(Path target, String pattern, String owner) {
    if (target.startsWith(options.uploadRoot())) {
      throw new IllegalArgumentException(
          "Pattern '"
              + pattern
              + "' under "
              + owner
              + " targets the Kyuubi upload root "
              + options.uploadRoot());
    }
  }
}
