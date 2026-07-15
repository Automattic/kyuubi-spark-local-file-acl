package com.automattic.kyuubi.spark.localfileacl;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
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
    Set<RuleRef> beforeAll = before.allRuleRefs();
    Set<RuleRef> afterAll = after.allRuleRefs();
    Set<RuleRef> afterActive = after.activeRuleRefs();
    Set<RuleRef> beforeUnresolved = before.unresolvedRefs();

    List<RuleChange> changes = new ArrayList<>();
    afterAll.stream()
        .filter(ref -> !beforeAll.contains(ref))
        .sorted(RULE_REF_ORDER)
        .forEach(ref -> changes.add(change(ChangeKind.ADDED, ref)));
    beforeAll.stream()
        .filter(ref -> !afterAll.contains(ref))
        .sorted(RULE_REF_ORDER)
        .forEach(ref -> changes.add(change(ChangeKind.REMOVED, ref)));
    // Resolved: this exact omitted rule is now active because its file appeared. Matched by rule
    // identity, not by path — if a different principal's rule for the same path was removed, that
    // is a removal, not a resolution of this one.
    before.unresolvedRules.stream()
        .filter(rule -> afterActive.contains(ref(rule)))
        .sorted(UNRESOLVED_ORDER)
        .forEach(rule -> changes.add(change(ChangeKind.RESOLVED, rule)));
    // Pending: this exact rule is omitted now and was not omitted before (again by identity).
    after.unresolvedRules.stream()
        .filter(rule -> !beforeUnresolved.contains(ref(rule)))
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

  private static RuleRef ref(UnresolvedRule rule) {
    return new RuleRef(rule.type(), rule.principal(), rule.pattern());
  }

  private Set<RuleRef> allRuleRefs() {
    Set<RuleRef> refs = activeRuleRefs();
    refs.addAll(unresolvedRefs());
    return refs;
  }

  private Set<RuleRef> activeRuleRefs() {
    Set<RuleRef> refs = new LinkedHashSet<>();
    userRules.forEach(
        (principal, rules) ->
            rules.forEach(rule -> refs.add(new RuleRef("user", principal, rule.patternText()))));
    groupRules.forEach(
        (principal, rules) ->
            rules.forEach(rule -> refs.add(new RuleRef("group", principal, rule.patternText()))));
    return refs;
  }

  private Set<RuleRef> unresolvedRefs() {
    Set<RuleRef> refs = new LinkedHashSet<>();
    unresolvedRules.forEach(rule -> refs.add(ref(rule)));
    return refs;
  }

  /**
   * The single definition of how an exact pattern is keyed for missing-file tracking, used by the
   * loader to populate {@link #unresolvedRules()} and by {@link PolicyStore} to re-resolve them.
   */
  static Path unresolvedKey(String pattern) {
    return Path.of(pattern).normalize();
  }
}
