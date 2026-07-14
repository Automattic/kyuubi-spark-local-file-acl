package com.automattic.kyuubi.spark.localfileacl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.apache.hadoop.conf.Configuration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class HadoopGroupResolverSpec {

  @BeforeAll
  static void configureStaticGroupMapping() {
    Configuration conf = new Configuration();
    conf.set("hadoop.security.group.mapping", StaticTestGroupsMapping.class.getName());
    TestSupport.installHadoopGroupMapping(conf);
  }

  @AfterAll
  static void restoreHadoopDefaults() {
    // Undo the JVM-wide UGI/Groups changes so later specs are not served synthetic groups.
    TestSupport.installHadoopGroupMapping(new Configuration());
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
