package com.automattic.kyuubi.spark.localfileacl;

import java.util.Set;

/** Resolves the primary and supplementary groups of an effective session user. */
public interface GroupResolver {

  Set<String> resolveGroups(String user) throws Exception;
}
