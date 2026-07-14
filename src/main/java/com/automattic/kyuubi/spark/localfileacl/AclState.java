package com.automattic.kyuubi.spark.localfileacl;

/** The atomically published outcome of the most recent ACL load or reload. */
public sealed interface AclState permits AclState.Valid, AclState.Invalid {

  record Valid(AclPolicy policy, String digest) implements AclState {}

  record Invalid(String error) implements AclState {}
}
