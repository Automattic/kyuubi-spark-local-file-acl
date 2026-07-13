package com.automattic.kyuubi.spark.localfileacl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.Groups;
import org.apache.hadoop.security.UserGroupInformation;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class HadoopGroupResolverSpec {

  @BeforeAll
  static void configureStaticGroupMapping() {
    Configuration conf = new Configuration();
    conf.set("hadoop.security.group.mapping", StaticTestGroupsMapping.class.getName());
    UserGroupInformation.setConfiguration(conf);
    // Replace the JVM-wide Groups singleton so createRemoteUser uses the static mapping.
    Groups.getUserToGroupsMappingServiceWithLoadedConfiguration(conf);
  }

  @Test
  void resolvesPrimaryAndSupplementaryGroups() throws Exception {
    HadoopGroupResolver resolver = new HadoopGroupResolver();
    assertEquals(Set.of("data-eng", "analysts"), resolver.resolveGroups("alice"));
    assertEquals(Set.of("admins"), resolver.resolveGroups("bob"));
  }

  @Test
  void returnsEmptySetWhenHadoopKnowsNoGroups() throws Exception {
    HadoopGroupResolver resolver = new HadoopGroupResolver();
    assertTrue(resolver.resolveGroups("stranger-with-no-groups").isEmpty());
  }
}
