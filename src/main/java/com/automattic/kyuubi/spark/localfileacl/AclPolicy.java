package com.automattic.kyuubi.spark.localfileacl;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Immutable compiled ACL snapshot: allow rules per username and per Hadoop group, plus the exact
 * rules that were omitted because their file did not exist (only possible when {@code
 * kyuubi.local.file.acl.fail.on.missing.files} is off). Each omitted rule retains its principal and
 * pattern so a change to it remains visible in the reload diff even while its file stays missing.
 */
public record AclPolicy(
    Map<String, List<CompiledRule>> userRules,
    Map<String, List<CompiledRule>> groupRules,
    Set<UnresolvedRule> unresolvedRules) {

  public AclPolicy {
    userRules = deepCopy(userRules);
    groupRules = deepCopy(groupRules);
    unresolvedRules = Set.copyOf(unresolvedRules);
  }

  /** An exact rule omitted for a missing file: its identity plus its normalized filesystem key. */
  public record UnresolvedRule(String type, String principal, String pattern, Path key) {}

  /** A single rule's identity, independent of whether it is currently active or omitted. */
  private record RuleRef(String type, String principal, String pattern) {}

  /**
   * One difference between two snapshots; {@code pattern} is a single value, never a joined list.
   */
  public record RuleChange(ChangeKind kind, String type, String principal, String pattern) {}

  public enum ChangeKind {
    ADDED, // a rule identity present now but not before
    REMOVED, // a rule identity present before but not now
    RESOLVED, // an omitted rule whose file appeared, so it is now active
    PENDING // a rule newly omitted because its file is missing
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

  /** Normalized filesystem keys of the omitted rules, as {@link PolicyStore} re-resolves them. */
  public Set<Path> unresolvedPaths() {
    return unresolvedRules.stream()
        .map(UnresolvedRule::key)
        .collect(Collectors.toUnmodifiableSet());
  }

  /**
   * What changed between two published snapshots, as a flat, deterministically ordered list of
   * single-valued changes. Active and omitted rules are diffed together by identity, so a rule that
   * moves between principals while its file stays missing still appears as a remove plus an add.
   */
  public static List<RuleChange> diff(AclPolicy before, AclPolicy after) {
    Set<RuleRef> beforeRefs = before.allRuleRefs();
    Set<RuleRef> afterRefs = after.allRuleRefs();
    Set<Path> beforeUnresolvedKeys = before.unresolvedKeys();
    Set<Path> afterUnresolvedKeys = after.unresolvedKeys();
    Set<Path> afterActiveKeys = after.activeExactKeys();

    List<RuleChange> changes = new ArrayList<>();
    afterRefs.stream()
        .filter(ref -> !beforeRefs.contains(ref))
        .sorted(RULE_REF_ORDER)
        .forEach(ref -> changes.add(change(ChangeKind.ADDED, ref)));
    beforeRefs.stream()
        .filter(ref -> !afterRefs.contains(ref))
        .sorted(RULE_REF_ORDER)
        .forEach(ref -> changes.add(change(ChangeKind.REMOVED, ref)));
    // Resolved: an omitted rule whose file appeared — its key left the unresolved set and now backs
    // an active rule (a key that merely left because the rule was deleted does not count).
    before.unresolvedRules.stream()
        .filter(
            rule ->
                !afterUnresolvedKeys.contains(rule.key()) && afterActiveKeys.contains(rule.key()))
        .sorted(UNRESOLVED_ORDER)
        .forEach(rule -> changes.add(change(ChangeKind.RESOLVED, rule)));
    // Pending: a rule newly omitted for a missing file.
    after.unresolvedRules.stream()
        .filter(rule -> !beforeUnresolvedKeys.contains(rule.key()))
        .sorted(UNRESOLVED_ORDER)
        .forEach(rule -> changes.add(change(ChangeKind.PENDING, rule)));
    return changes;
  }

  private static final Comparator<RuleRef> RULE_REF_ORDER =
      Comparator.comparing(RuleRef::type)
          .thenComparing(RuleRef::principal)
          .thenComparing(RuleRef::pattern);

  private static final Comparator<UnresolvedRule> UNRESOLVED_ORDER =
      Comparator.comparing(UnresolvedRule::type)
          .thenComparing(UnresolvedRule::principal)
          .thenComparing(UnresolvedRule::pattern);

  private static RuleChange change(ChangeKind kind, RuleRef ref) {
    return new RuleChange(kind, ref.type(), ref.principal(), ref.pattern());
  }

  private static RuleChange change(ChangeKind kind, UnresolvedRule rule) {
    return new RuleChange(kind, rule.type(), rule.principal(), rule.pattern());
  }

  private Set<RuleRef> allRuleRefs() {
    Set<RuleRef> refs = new LinkedHashSet<>();
    userRules.forEach(
        (principal, rules) ->
            rules.forEach(rule -> refs.add(new RuleRef("user", principal, rule.patternText()))));
    groupRules.forEach(
        (principal, rules) ->
            rules.forEach(rule -> refs.add(new RuleRef("group", principal, rule.patternText()))));
    unresolvedRules.forEach(
        rule -> refs.add(new RuleRef(rule.type(), rule.principal(), rule.pattern())));
    return refs;
  }

  private Set<Path> unresolvedKeys() {
    Set<Path> keys = new HashSet<>();
    unresolvedRules.forEach(rule -> keys.add(rule.key()));
    return keys;
  }

  private Set<Path> activeExactKeys() {
    Set<Path> keys = new HashSet<>();
    collectExactKeys(userRules, keys);
    collectExactKeys(groupRules, keys);
    return keys;
  }

  private static void collectExactKeys(Map<String, List<CompiledRule>> rules, Set<Path> collected) {
    rules
        .values()
        .forEach(
            principalRules ->
                principalRules.forEach(
                    rule -> {
                      if (rule instanceof CompiledRule.Exact exact) {
                        collected.add(unresolvedKey(exact.patternText()));
                      }
                    }));
  }

  /**
   * The single definition of how an exact pattern is keyed for missing-file tracking. Both the
   * loader (which populates {@link #unresolvedRules()}) and {@link #diff} key on this, so the
   * "resolved" detection cannot silently drift from how the omitted rules were keyed.
   */
  static Path unresolvedKey(String pattern) {
    return Path.of(pattern).normalize();
  }
}
