package com.automattic.kyuubi.spark.localfileacl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.Groups;
import org.apache.hadoop.security.UserGroupInformation;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class HadoopGroupResolverSpec {

  @BeforeAll
  static void configureStaticGroupMapping() {
    // Other specs exercise the real HadoopGroupResolver first (class order is OS-dependent),
    // which initializes UGI's static Groups machinery with the default shell mapping. Reset it
    // so the static test mapping below takes effect regardless of execution order.
    UserGroupInformation.reset();
    Configuration conf = new Configuration();
    conf.set("hadoop.security.group.mapping", StaticTestGroupsMapping.class.getName());
    // Replace the JVM-wide Groups singleton BEFORE setConfiguration: UGI.initialize captures
    // Groups.getUserToGroupsMappingService(conf), which returns the existing singleton if any
    // other spec already created it with the default shell mapping.
    Groups.getUserToGroupsMappingServiceWithLoadedConfiguration(conf);
    UserGroupInformation.setConfiguration(conf);
  }

  @AfterAll
  static void restoreHadoopDefaults() {
    // Undo the JVM-wide UGI/Groups changes so later specs are not served synthetic groups.
    UserGroupInformation.reset();
    Configuration conf = new Configuration();
    Groups.getUserToGroupsMappingServiceWithLoadedConfiguration(conf);
    UserGroupInformation.setConfiguration(conf);
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
