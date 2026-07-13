package com.automattic.kyuubi.spark.localfileacl;

import java.time.Instant;

/** The atomically published outcome of the most recent ACL load or reload. */
public sealed interface AclState permits AclState.Valid, AclState.Invalid {

  record Valid(AclPolicy policy, String digest, Instant loadedAt) implements AclState {}

  record Invalid(String error, Instant detectedAt) implements AclState {}
}
