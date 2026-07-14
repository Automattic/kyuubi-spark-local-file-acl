# kyuubi-spark-local-file-acl

A Kyuubi `SessionConfAdvisor` plugin that restricts which files a user may supply from the Kyuubi
server's local filesystem through Spark file-distribution configuration.

`spark-submit` reads local paths as the Kyuubi service user, so an untrusted session could
otherwise distribute server configuration, keytabs, or TLS keys to its driver and executors. This
plugin authorizes every server-local input file against a YAML ACL (by username and Hadoop group)
before Kyuubi launches `spark-submit`. Remote URIs (`hdfs:`, `s3a:`, `http:`, ...) are outside its
scope and remain subject to their storage system's authorization.

Built and tested against Kyuubi 1.11.1 on JDK 17 and 21.

## Policed configuration keys

Keys are normalized exactly like Kyuubi's `SparkProcessBuilder.convertConfigKey`, so unqualified
aliases (`files`, `jars`, `yarn.dist.files`, ...) are policed alongside their `spark.`-qualified
forms. Defaults:

| Key | Cardinality |
| --- | --- |
| `spark.files`, `spark.jars`, `spark.archives` | list |
| `spark.yarn.jars`, `spark.yarn.dist.files`, `spark.yarn.dist.pyFiles`, `spark.yarn.dist.jars`, `spark.yarn.dist.archives` | list |
| `spark.submit.pyFiles` | list |
| `spark.kerberos.keytab`, `spark.yarn.keytab`, `spark.kubernetes.kerberos.krb5.path` | scalar |

`spark.kubernetes.file.upload.path` is intentionally not policed (upload destination, not an input
file). The effective set is `(defaults ∪ extra keys) − excluded keys`; see the escape hatches
below. The effective keys and cardinalities are logged at `INFO` during initialization.

## Installation

1. Build: `mvn package` (JDK 17+). Copy
   `target/kyuubi-spark-local-file-acl-<version>.jar` into the Kyuubi server classpath (e.g.
   `$KYUUBI_HOME/jars`). SnakeYAML is shaded and relocated; nothing else is bundled.
2. Register the advisor in `kyuubi-defaults.conf`:

   ```properties
   kyuubi.session.conf.advisor=com.automattic.kyuubi.spark.localfileacl.SparkLocalFileAclAdvisor
   # Append to any existing ignore list; see "Batch upload exemption" for why this is required
   # and why the restrict list must NOT be used for these keys.
   kyuubi.session.conf.ignore.list=kyuubi.batch.resource.uploaded,kyuubi.batch.id
   ```

3. Pass plugin settings as JVM system properties in `kyuubi-env.sh` so they can never enter
   session configuration or the generated Spark configuration:

   ```bash
   export KYUUBI_JAVA_OPTS="$KYUUBI_JAVA_OPTS \
     -Dkyuubi.local.file.acl.rules.file=/etc/kyuubi/kyuubi-local-file-acl.yaml \
     -Dkyuubi.local.file.acl.reload.interval=PT60S"
   ```

| System property | Default | Meaning |
| --- | --- | --- |
| `kyuubi.local.file.acl.rules.file` | `$KYUUBI_CONF_DIR/kyuubi-local-file-acl.yaml` | ACL policy location |
| `kyuubi.local.file.acl.reload.interval` | `PT60S` | ISO-8601 duration between reload checks |
| `kyuubi.local.file.acl.extra.keys` | (none) | Additional policed keys, e.g. `spark.custom.files:list,spark.custom.keytab:scalar` |
| `kyuubi.local.file.acl.excluded.keys` | (none) | Keys removed from the effective set; exclusions win over defaults and extras |
| `kyuubi.local.file.acl.upload.root` | `$KYUUBI_WORK_DIR_ROOT/upload`, else `${user.dir}/upload` | Must match Kyuubi's upload work dir; created if absent and canonicalized at startup (startup fails otherwise) |
| `kyuubi.local.file.acl.expected.owner` | (none) | When set, every reload requires the ACL file — and every ancestor directory of it — to be owned by this OS user (or root, for system directories) |

Escape-hatch entries are normalized with the same key rules; malformed entries, unknown
cardinalities, conflicting duplicates, and exclusions that match nothing fail plugin
initialization (and therefore server session handling) at startup. These settings are
startup-only — they are not part of YAML hot reload.

## ACL file

```yaml
version: 1

users:
  alice:
    allow:
      - '/opt/kyuubi/resources/alice/*.conf'
      - '/opt/kyuubi/resources/libraries/**/alice-*.jar'

groups:
  data-engineering:
    allow:
      - '/opt/kyuubi/resources/shared/*.properties'
      - '/opt/kyuubi/certificates/{development,staging}/*.pem'
```

- Effective permissions are the union of the username's rules and the rules of every Hadoop group
  containing the user (resolved via `UserGroupInformation`, i.e. Kyuubi's `HadoopGroupProvider`
  behavior). There are no deny rules; no match means denied.
- Patterns use Java NIO `glob:` syntax (`*`, `**`, `?`, `[abc]`, `{one,two}`); a pattern without
  metacharacters is an exact-file rule that must resolve via `toRealPath()` at load time — an
  exact rule naming a nonexistent file invalidates the policy rather than silently authorizing a
  file created later.
- Patterns must be absolute local paths, without URI schemes or `..` segments, and must not target
  the Kyuubi upload root. Duplicate YAML keys (principals, `allow` fields) are rejected.
- Submitted values must identify concrete files: globs, relative paths, `file` URIs with an
  authority or query, missing files, and non-regular files are rejected. `#alias` fragments are
  stripped; paths are canonicalized with `toRealPath()` before matching, so symlinks cannot
  escape an allowed tree at validation time.

The file must be owned by the Kyuubi administrator (enforce with
`kyuubi.local.file.acl.expected.owner`, which also requires every ancestor directory to be owned
by that user or root — otherwise a directory-entry swap could substitute the policy). The
enforced permission rule is: no group- or world-*write* bit on the file or any ancestor
directory, except sticky directories such as `/tmp` (mode `1777`), where the sticky bit already
prevents other users from swapping entries they do not own. Read bits are not enforced —
`0644` is accepted — but `0600` or `0640` is recommended since the policy reveals server path
layout; ancestor directories need execute permission, so `0700`, `0750`, or `0755` are all fine. Each reload re-verifies all of this, reads through a stream bounded at 1 MiB,
and accepts the content only when the file key, size, and modification time are identical before
and after the read and a second integrity check passes — so a file swapped or rewritten mid-read
is never accepted. Update it atomically:

```bash
cp kyuubi-local-file-acl.yaml kyuubi-local-file-acl.yaml.tmp
vi kyuubi-local-file-acl.yaml.tmp
chmod 0640 kyuubi-local-file-acl.yaml.tmp
chown kyuubi-admin: kyuubi-local-file-acl.yaml.tmp   # the configured expected.owner, if set
mv kyuubi-local-file-acl.yaml.tmp kyuubi-local-file-acl.yaml   # same filesystem
```

## Hot reload and failure behavior

The policy is an immutable snapshot behind an atomic reference. On a non-blocking interval check,
one request thread re-reads the file, skips reparsing when the SHA-256 digest is unchanged, and
atomically publishes the new snapshot (modification time is deliberately not trusted).

The plugin fails closed for local resources when: the initial ACL cannot be loaded (plugin
initialization fails), a reload produces an invalid state (missing/unreadable/malformed file,
invalid pattern, loose permissions), Hadoop group resolution fails, a local URI is malformed or
missing, or no pattern matches. While the state is invalid the last valid policy is NOT used —
submissions with local resources are rejected until a valid policy is installed. Sessions without
policed keys, or with remote-only resources, are unaffected. Current-batch upload exemptions also
remain in effect while the state is invalid: they authorize only files the batch itself staged,
canonically confined to its own upload directory, and never consult ACL rules — so an ACL outage
does not fail batches that reference nothing but their own uploads. Denials throw
`org.apache.kyuubi.KyuubiException` naming the user, configuration key, and path; grants and
denials are audit-logged through SLF4J into Kyuubi's normal logging.

## Batch upload exemption

Files uploaded via the REST batch API are staged under `<upload-root>/<batch-id>/` before the
advisor runs and are exempted from ACL rules — but only for the batch that uploaded them. Any
other path under the shared upload root is denied unconditionally, even when a broad ACL glob
matches it, so one batch can never reference another batch's uploads.

The exemption trusts Kyuubi's reserved keys `kyuubi.batch.resource.uploaded` and
`kyuubi.batch.id`. Interactive clients must be prevented from forging them with:

```properties
kyuubi.session.conf.ignore.list=kyuubi.batch.resource.uploaded,kyuubi.batch.id
```

**Do not use `kyuubi.session.conf.restrict.list` for these keys on Kyuubi 1.11.x.** Kyuubi itself
injects both keys into every REST batch conf, and `AbstractSession` eagerly validates the full
batch conf against the restrict list, so restricting them fails every batch submission (verified
against 1.11.1). The ignore list strips the keys from interactive sessions (neutralizing forgery)
while the separate batch ignore list — which must NOT contain these keys — leaves batch conf
intact.

## Optional Kyuubi 1.12+ global hardening

Kyuubi 1.12 adds `kyuubi.server.spark.file.config.list`
([KYUUBI #7415](https://github.com/apache/kyuubi/issues/7415)), extending the server's built-in
local-directory validation. Use it as defense in depth; it also covers the batch main `resource`,
which is invisible to `SessionConfAdvisor` (keep `kyuubi.session.local.dir.allow.list` configured
for that resource on all versions):

```properties
kyuubi.session.local.dir.allow.list=/opt/kyuubi/resources
kyuubi.server.spark.file.config.list=files,jars,archives,yarn.jars,yarn.dist.files,yarn.dist.pyFiles,submit.pyFiles,yarn.dist.jars,yarn.dist.archives,kerberos.keytab,yarn.keytab,kubernetes.kerberos.krb5.path
```

The global directory list is an upper bound: every path allowed by the YAML policy should be
beneath one of its roots. The plugin remains independently correct without it.

## Security limitations

- TOCTOU: the advisor validates a canonical path before `spark-submit` reads it; a file replaced
  between authorization and use is not detected. Eliminating this requires staging a trusted
  immutable copy, which is out of scope.
- Multipart upload filename normalization and containment are Kyuubi server behavior, not
  controlled by this plugin; only the staged canonical path is authorized.
- Rejection relies on Kyuubi aborting session construction when `getConfOverlay` throws (implicit
  behavior, verified on 1.11.1). Re-verify exception propagation, `convertConfigKey` equivalence,
  and the reserved-key injection behavior on every Kyuubi upgrade. Batch v2 and recovered batches
  construct sessions asynchronously, so a rejection can surface as a batch failure rather than an
  immediate REST error.

## Development

```bash
mvn test     # unit tests
mvn verify   # + integration tests booting an embedded Kyuubi 1.11.1 server (no Spark needed)
mvn package  # shaded plugin jar in target/
```

Integration tests port Kyuubi's `WithKyuubiServer` bootstrap to JUnit: an embedded ZooKeeper plus
a real KyuubiServer with this advisor installed, exercising THRIFT interactive rejection, REST
batch rejection, the forged-exemption defense, and advisor pass-through for authorized batches.

## License

Apache License, Version 2.0 — see [LICENSE](LICENSE) ([LICENSE-binary](LICENSE-binary) /
[NOTICE-binary](NOTICE-binary) cover the shaded jar, which bundles relocated SnakeYAML).
