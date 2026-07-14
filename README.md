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
     -Dkyuubi.local.file.acl.reload.interval=PT60S \
     -Dkyuubi.local.file.acl.wildcards.enabled=true"
   ```

   The example ACL below uses glob patterns, which require
   `kyuubi.local.file.acl.wildcards.enabled=true`. Drop that flag if your policy names exact
   files only.

| System property | Default | Meaning |
| --- | --- | --- |
| `kyuubi.local.file.acl.rules.file` | `$KYUUBI_CONF_DIR/kyuubi-local-file-acl.yaml` | ACL policy location. With neither this property nor `KYUUBI_CONF_DIR` set, initialization fails |
| `kyuubi.local.file.acl.reload.interval` | `PT60S` | ISO-8601 duration between reload checks |
| `kyuubi.local.file.acl.extra.keys` | (none) | Additional policed keys, e.g. `spark.custom.files:list,spark.custom.keytab:scalar` |
| `kyuubi.local.file.acl.excluded.keys` | (none) | Keys removed from the effective set; exclusions win over defaults and extras |
| `kyuubi.local.file.acl.upload.root` | `$KYUUBI_WORK_DIR_ROOT/upload`, else `${user.dir}/upload` | Must match Kyuubi's upload work dir; created if absent and canonicalized at startup (startup fails otherwise) |
| `kyuubi.local.file.acl.expected.owner` | (none) | When set, every reload requires the ACL file to be owned by this OS user, and every ancestor directory of it to be owned by this user or by root |
| `kyuubi.local.file.acl.wildcards.enabled` | `false` | Whether ACL patterns may use glob matching. While disabled, any pattern containing `*`, `?`, `[`, `]`, `{`, or `}` makes the policy invalid |
| `kyuubi.local.file.acl.fail.on.missing.files` | `true` | Whether an exact rule naming a nonexistent file makes the policy invalid. When `false`, the rule is logged at `ERROR` and omitted |

The two boolean properties accept only `true` or `false` (case-insensitively); a blank or
unrecognized value fails plugin initialization rather than silently selecting a
security-sensitive mode.

Escape-hatch entries are normalized with the same key rules; malformed entries, unknown
cardinalities, conflicting duplicates, and exclusions that match nothing fail plugin
initialization (and therefore server session handling) at startup. These settings are
startup-only — they are not part of YAML hot reload.

**Upgrading from 1.0.x to 2.0.0** — two breaking changes, both of which fail loudly at startup
rather than silently weakening enforcement:

- Wildcard matching used to be unconditional and is now off by default. A deployment whose ACL uses
  glob patterns must set `-Dkyuubi.local.file.acl.wildcards.enabled=true`.
- The ACL schema is `version: 2`: each principal maps straight to its list of patterns (see below).

Either one left unaddressed fails plugin initialization, and the server then rejects every session
carrying a policed key.

## ACL file

```yaml
version: 2

users:
  alice:
    - '/opt/kyuubi/resources/alice/*.conf'
    - '/opt/kyuubi/resources/libraries/**/alice-*.jar'

groups:
  data-engineering:
    - '/opt/kyuubi/resources/shared/*.properties'
    - '/opt/kyuubi/certificates/{development,staging}/*.pem'
```

- Each principal maps directly to its list of allowed patterns. There are no deny rules; no match
  means denied. Any other shape — a nested mapping, a bare string, or a principal with no value at
  all — is rejected; a principal that intentionally grants nothing is written `alice: []`.
- Effective permissions are the union of the username's rules and the rules of every Hadoop group
  containing the user (resolved via `UserGroupInformation`, i.e. Kyuubi's `HadoopGroupProvider`
  behavior).
- Patterns use Java NIO `glob:` syntax (`*`, `**`, `?`, `[abc]`, `{one,two}`) **only when
  `kyuubi.local.file.acl.wildcards.enabled=true`**. While wildcards are disabled (the default), a
  pattern containing a glob metacharacter is rejected with an error naming the property — it is
  never reinterpreted as a literal filename — and the policy is invalid. A glob that currently
  matches no file stays valid: it legitimately describes files created later.
- A pattern without metacharacters is an exact-file rule that must resolve via `toRealPath()` at
  load time. By default a nonexistent file invalidates the policy rather than silently authorizing
  a file created later. With `kyuubi.local.file.acl.fail.on.missing.files=false` the rule is
  instead logged at `ERROR` and omitted: it authorizes nothing, its siblings stay in effect, and
  it activates on a later reload once the file exists (see below). Only a genuinely absent file is
  tolerated — permission errors, symlink loops, and other I/O failures still invalidate the
  policy.
- Patterns must be absolute local paths, without URI schemes or `..` segments, and must not target
  the Kyuubi upload root. Duplicate principals are rejected rather than silently collapsed.
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

The policy is an immutable snapshot published through a volatile reference, so a request thread
sees either the whole old policy or the whole new one. On a non-blocking interval check, one
request thread re-reads the file, skips reparsing when the SHA-256 digest is unchanged, and
publishes the new snapshot (modification time is deliberately not trusted).

The digest fast path has one exception: when the active policy carries exact rules that were
omitted for missing files, each check re-resolves those paths exactly as the loader does. Only a
still-absent file keeps the fast path. If the path now resolves — or fails for any other reason,
such as a symlink loop or an unreadable parent — a full reparse is forced, which then either
activates the rule or invalidates the policy, matching what the loader would have done at load
time. An omitted rule therefore activates within one reload interval of its file appearing,
without an ACL edit or a restart, and only through that reparse, which canonicalizes the path and
re-runs every policy check. It is never matched lexically. While the file stays absent, the
reparse is skipped as usual, so nothing churns and the `ERROR` is not re-logged every interval.

The plugin fails closed for local resources when: the initial ACL cannot be loaded (plugin
initialization fails), a reload produces an invalid state (missing/unreadable/malformed file, loose
permissions, an invalid pattern, a glob pattern while wildcards are disabled, or an exact rule
whose file does not exist while `fail.on.missing.files` is on), Hadoop group resolution fails, a
local URI is malformed or missing, or no pattern matches. While the state is invalid the last valid policy is NOT used —
submissions with local resources are rejected until a valid policy is installed. Sessions without
policed keys, or with remote-only resources, are unaffected. Current-batch upload exemptions also
remain in effect while the state is invalid: they authorize only files the batch itself staged,
canonically confined to its own upload directory, and never consult ACL rules — so an ACL outage
does not fail batches that reference nothing but their own uploads. Denials throw
`org.apache.kyuubi.KyuubiException` naming the user, configuration key, and path, and are recorded
in the audit log below.

## Audit log

Every authorization decision the plugin makes is emitted as one single-line record on a dedicated
SLF4J category:

```text
com.automattic.kyuubi.spark.localfileacl.audit
```

Grants log at `INFO`, denials at `WARN`, in a fixed logfmt-style schema:

```text
event=local_file_acl decision=ALLOW user="alice" key="spark.files" resource="/opt/kyuubi/resources/alice/app.conf" reason="user-rule" principal_type="user" principal="alice" pattern="/opt/kyuubi/resources/alice/*.conf"
event=local_file_acl decision=DENY user="mallory" key="spark.files" resource="/etc/kyuubi/kyuubi.keytab" reason="no-matching-rule" principal_type="" principal="" pattern=""
```

- `reason` is one of `user-rule`, `group-rule`, `upload-exemption` (grants) or `no-matching-rule`,
  `cross-batch-upload`, `invalid-acl-state`, `group-resolution-failed`, `invalid-resource`
  (denials). Fields that do not apply to a decision are present with an empty value, so the schema
  is stable for downstream parsing.
- Every value is escaped: quotes, backslashes, and every ISO control character (C0, DEL, and C1 —
  which includes U+0085 NEXT LINE), plus U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR,
  which Unicode-aware log processors treat as line breaks. A crafted username or path can neither
  forge a record nor split a decision across lines.
- Exactly one record per **evaluated** local resource. Validation is fail-fast: once a resource is
  denied the submission is rejected, and the resources after it are never evaluated and never get
  a fabricated record. Remote URIs and unpoliced keys produce no records — the plugin makes no
  decision about them.

The plugin bundles no logging configuration. Route the category to its own file through Kyuubi's
Log4j2 configuration (`$KYUUBI_CONF_DIR/log4j2.xml`), with additivity off so the records do not
also land in the server log:

```xml
<RollingFile name="audit" fileName="${sys:kyuubi.log.path}/kyuubi-local-file-acl-audit.log"
             filePattern="${sys:kyuubi.log.path}/kyuubi-local-file-acl-audit-%d{yyyy-MM-dd}.log.gz">
  <PatternLayout pattern="%d{ISO8601} %-5level %msg%n"/>
  <Policies><TimeBasedTriggeringPolicy/></Policies>
</RollingFile>

<Logger name="com.automattic.kyuubi.spark.localfileacl.audit" level="info" additivity="false">
  <AppenderRef ref="audit"/>
</Logger>
```

Retention, file permissions, shipping, and durability of that file are operator responsibilities.

## Batch upload exemption

### Why an exemption exists

The REST batch API lets a client upload its jar with the submission. Kyuubi stages that file at
`<upload-root>/<batch-id>/<filename>` **before** the advisor runs, then passes the staged
server-local path in the session configuration. To the ACL that path is indistinguishable from
`/etc/kyuubi/kyuubi.keytab` — it is just a local file on the Kyuubi server — so it would be denied:
no administrator can write a rule for a path containing a batch UUID that does not exist yet.
Batch uploads would stop working entirely.

So a file the batch itself uploaded is authorized without consulting the ACL.

### Why it is scoped to a single batch

The upload root is shared by every batch. An exemption of the form "anything under the upload root
is fine" would let batch B name `<upload-root>/<batch-A-id>/app.jar` and read what batch A — quite
possibly a different user — uploaded.

The check is therefore two-stage. A canonical path under the upload root is allowed only when it
is also under `<upload-root>/<this-batch-id>/`. Any other path beneath the upload root is **denied
unconditionally and never falls through to the ACL rules** — so an administrator who writes a broad
glob like `/**` does not accidentally re-open cross-batch access. Paths under the upload root are
decided entirely by this logic, never by patterns.

The exemption also requires the batch id to parse as a UUID and its upload directory to exist, and
it canonicalizes with `toRealPath()` before comparing, so a symlink planted inside an upload
directory cannot point at `/etc` and inherit the exemption.

Because it never consults ACL rules, the exemption keeps working while the ACL state is invalid: a
broken policy file does not fail batches that reference nothing but their own uploads.

### Why the ignore list is mandatory

The exemption trusts two keys Kyuubi injects into batch session configuration:
`kyuubi.batch.resource.uploaded` and `kyuubi.batch.id`. Nothing in the session configuration proves
they came from the server — an interactive JDBC client can send any key it likes in its connection
string:

```text
jdbc:kyuubi://host:10009/;?kyuubi.batch.resource.uploaded=true;kyuubi.batch.id=<someone-elses-batch-uuid>;spark.files=<upload-root>/<that-uuid>/app.jar
```

Without a defense, that forges the exemption and reads another batch's upload. Configure the
server to strip both keys from interactive sessions:

```properties
kyuubi.session.conf.ignore.list=kyuubi.batch.resource.uploaded,kyuubi.batch.id
```

The advisor then never sees the forged keys, finds no current batch, and denies the path as a
cross-batch upload (`reason="cross-batch-upload"` in the audit log).
`KyuubiServerITSpec.interactiveSessionCannotForgeReservedUploadKeys` runs exactly this attack
against a real server.

### Do not use the restrict list for these keys on Kyuubi 1.11.x

`kyuubi.session.conf.restrict.list` is the intuitive choice — it makes Kyuubi *reject* a session
that sets a listed key, rather than quietly dropping it — and it **breaks every batch submission**.

Both lists are checked in `SessionManager.validateKey`: a restricted key throws
`KyuubiSQLException`, an ignored key is dropped with a warning. Stripping is all this plugin needs
(the advisor then finds no current batch and denies the path), and rejecting is what causes the
damage, because Kyuubi injects these two keys itself. `BatchesResource` adds
`kyuubi.batch.id` and `kyuubi.batch.resource.uploaded` to the configuration of *every* batch, so
they are present whether or not the client sent them.

`KyuubiBatchSession` appears to be immune: it overrides `normalizedConf` to use
`SessionManager.validateBatchConf`, which consults only the *batch* ignore list and never the
restrict list. But overriding a Scala `val` does not remove the superclass's initializer.
`AbstractSession` still declares

```scala
val normalizedConf: Map[String, String] = sessionManager.validateAndNormalizeConf(conf)
```

and that initializer runs during superclass construction, over the complete batch configuration,
using the restrict-list-enforcing code path. Its result is discarded — the override wins — but its
exception is not. The server therefore rejects its own injected keys and every batch submission
fails, before the advisor is ever consulted. Verified against 1.11.1: with these keys in the
restrict list, all REST batches fail; with them in the session ignore list, they pass.

Also keep them **out** of `kyuubi.batch.conf.ignore.list`. That list is the one `validateBatchConf`
consults, so it would strip the keys from legitimate batch configuration, leaving the advisor
unable to identify the current batch and denying every batch upload as a cross-batch access — the
mirror image of the restrict-list failure.

| Configuration | Interactive forgery | Legitimate batch uploads |
| --- | --- | --- |
| Neither list | **Forgeable** — one batch reads another's uploads | Work |
| `kyuubi.session.conf.ignore.list` (correct) | Keys stripped, path denied | Work |
| `kyuubi.session.conf.restrict.list` | Session rejected | **All batches fail** (server's own keys) |
| `kyuubi.batch.conf.ignore.list` | Unaffected | **All uploads denied** (exemption never applies) |

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
mvn test              # unit tests
mvn verify            # + integration tests (embedded Kyuubi 1.11.1 server, no Spark needed),
                      #   Spotless format check, SpotBugs analysis, Enforcer rules
mvn package           # shaded plugin jar in target/
mvn spotless:apply    # reformat sources (google-java-format); run before committing
```

Code style is google-java-format, enforced by Spotless at `verify`; SpotBugs runs at max effort
with justified exclusions in `spotbugs-exclude.xml`; Enforcer requires Maven 3.8+ and JDK 17+.
`.mvn/jvm.config` carries the `--add-exports` flags google-java-format needs on JDK 17+.

Integration tests port Kyuubi's `WithKyuubiServer` bootstrap to JUnit: an embedded ZooKeeper plus
a real KyuubiServer with this advisor installed, exercising THRIFT interactive rejection, REST
batch rejection, the forged-exemption defense, and advisor pass-through for authorized batches.

## License

Apache License, Version 2.0 — see [LICENSE](LICENSE) ([LICENSE-binary](LICENSE-binary) /
[NOTICE-binary](NOTICE-binary) cover the shaded jar, which bundles relocated SnakeYAML).
