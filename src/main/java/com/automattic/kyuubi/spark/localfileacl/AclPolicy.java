package com.automattic.kyuubi.spark.localfileacl;

import java.nio.file.Path;
import java.util.LinkedHashMap;
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
}
