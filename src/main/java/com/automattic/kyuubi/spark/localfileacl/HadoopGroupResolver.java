package com.automattic.kyuubi.spark.localfileacl;

import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.hadoop.security.UserGroupInformation;

/**
 * Resolves groups with Hadoop's configured group mapping and its built-in cache, matching
 * Kyuubi's {@code HadoopGroupProvider} behavior.
 */
public final class HadoopGroupResolver implements GroupResolver {

  @Override
  public Set<String> resolveGroups(String user) throws Exception {
    String[] groups = UserGroupInformation.createRemoteUser(user).getGroupNames();
    Set<String> result = new LinkedHashSet<>();
    for (String group : groups) {
      result.add(group);
    }
    return result;
  }
}
