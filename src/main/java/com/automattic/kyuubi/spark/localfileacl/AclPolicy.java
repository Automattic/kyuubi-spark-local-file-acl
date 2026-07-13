package com.automattic.kyuubi.spark.localfileacl;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Immutable compiled ACL snapshot: allow rules per username and per Hadoop group. */
public record AclPolicy(
    Map<String, List<CompiledRule>> userRules,
    Map<String, List<CompiledRule>> groupRules) {

  public AclPolicy {
    userRules = deepCopy(userRules);
    groupRules = deepCopy(groupRules);
  }

  private static Map<String, List<CompiledRule>> deepCopy(Map<String, List<CompiledRule>> rules) {
    Map<String, List<CompiledRule>> copy = new LinkedHashMap<>();
    rules.forEach((principal, principalRules) -> copy.put(principal, List.copyOf(principalRules)));
    return java.util.Collections.unmodifiableMap(copy);
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
