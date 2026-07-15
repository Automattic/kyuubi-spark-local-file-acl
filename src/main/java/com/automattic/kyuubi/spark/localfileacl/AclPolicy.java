package com.automattic.kyuubi.spark.localfileacl;

import java.nio.file.Path;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Immutable compiled ACL snapshot: allow rules per username and per Hadoop group, plus the
 * normalized paths of exact rules that were omitted because their file did not exist (only possible
 * when {@code kyuubi.local.file.acl.fail.on.missing.files} is off).
 */
public record AclPolicy(
    Map<String, List<CompiledRule>> userRules,
    Map<String, List<CompiledRule>> groupRules,
    Set<Path> unresolvedPaths) {

  public AclPolicy {
    userRules = deepCopy(userRules);
    groupRules = deepCopy(groupRules);
    unresolvedPaths = Set.copyOf(unresolvedPaths);
  }

  private static Map<String, List<CompiledRule>> deepCopy(Map<String, List<CompiledRule>> rules) {
    Map<String, List<CompiledRule>> copy = new LinkedHashMap<>();
    rules.forEach((principal, principalRules) -> copy.put(principal, List.copyOf(principalRules)));
    return Map.copyOf(copy);
  }

  public List<CompiledRule> rulesForUser(String user) {
    return userRules.getOrDefault(user, List.of());
  }

  public List<CompiledRule> rulesForGroup(String group) {
    return groupRules.getOrDefault(group, List.of());
  }

  public int ruleCount() {
    return userRules.values().stream().mapToInt(List::size).sum()
        + groupRules.values().stream().mapToInt(List::size).sum();
  }

  /**
   * What changed between two published snapshots, for the reload audit event. {@code addedRules}
   * and {@code removedRules} are stable rule identities ({@code user:alice:/path}); {@code
   * resolvedPaths} are exact paths that were unresolved before and now have an active rule (a
   * missing file that appeared); {@code pendingPaths} are exact paths newly omitted for a missing
   * file.
   */
  public record ReloadDiff(
      List<String> addedRules,
      List<String> removedRules,
      List<String> resolvedPaths,
      List<String> pendingPaths) {

    public static final ReloadDiff EMPTY =
        new ReloadDiff(List.of(), List.of(), List.of(), List.of());

    public ReloadDiff {
      addedRules = List.copyOf(addedRules);
      removedRules = List.copyOf(removedRules);
      resolvedPaths = List.copyOf(resolvedPaths);
      pendingPaths = List.copyOf(pendingPaths);
    }
  }

  public static ReloadDiff diff(AclPolicy before, AclPolicy after) {
    Set<String> beforeRules = before.ruleIdentities();
    Set<String> afterRules = after.ruleIdentities();
    List<String> added =
        afterRules.stream().filter(rule -> !beforeRules.contains(rule)).sorted().toList();
    List<String> removed =
        beforeRules.stream().filter(rule -> !afterRules.contains(rule)).sorted().toList();

    // A path counts as resolved only if it left the unresolved set AND now backs an active rule;
    // a path that left because its rule was deleted is not a file that "became available".
    Set<Path> nowActiveExact = after.activeExactPaths();
    List<String> resolved =
        before.unresolvedPaths.stream()
            .filter(path -> !after.unresolvedPaths.contains(path) && nowActiveExact.contains(path))
            .map(Path::toString)
            .sorted()
            .toList();
    List<String> pending =
        after.unresolvedPaths.stream()
            .filter(path -> !before.unresolvedPaths.contains(path))
            .map(Path::toString)
            .sorted()
            .toList();
    return new ReloadDiff(added, removed, resolved, pending);
  }

  private Set<String> ruleIdentities() {
    Set<String> identities = new LinkedHashSet<>();
    userRules.forEach(
        (principal, rules) ->
            rules.forEach(rule -> identities.add("user:" + principal + ":" + rule.patternText())));
    groupRules.forEach(
        (principal, rules) ->
            rules.forEach(rule -> identities.add("group:" + principal + ":" + rule.patternText())));
    return identities;
  }

  /** Normalized paths of the exact rules currently active, keyed as the unresolved set is. */
  private Set<Path> activeExactPaths() {
    Set<Path> paths = new HashSet<>();
    collectExactPaths(userRules, paths);
    collectExactPaths(groupRules, paths);
    return paths;
  }

  private static void collectExactPaths(
      Map<String, List<CompiledRule>> rules, Set<Path> collected) {
    rules
        .values()
        .forEach(
            principalRules ->
                principalRules.forEach(
                    rule -> {
                      if (rule instanceof CompiledRule.Exact exact) {
                        collected.add(Path.of(exact.patternText()).normalize());
                      }
                    }));
  }
}
