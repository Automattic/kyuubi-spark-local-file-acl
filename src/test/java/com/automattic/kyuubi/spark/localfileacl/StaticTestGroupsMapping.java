package com.automattic.kyuubi.spark.localfileacl;

import java.util.List;
import java.util.Map;

import org.apache.hadoop.security.GroupMappingServiceProvider;

/** Deterministic Hadoop group mapping for {@link HadoopGroupResolverSpec}. */
public class StaticTestGroupsMapping implements GroupMappingServiceProvider {

  static final Map<String, List<String>> GROUPS = Map.of(
      "alice", List.of("data-eng", "analysts"),
      "bob", List.of("admins"));

  @Override
  public List<String> getGroups(String user) {
    return GROUPS.getOrDefault(user, List.of());
  }

  @Override
  public void cacheGroupsRefresh() {}

  @Override
  public void cacheGroupsAdd(List<String> groups) {}
}
