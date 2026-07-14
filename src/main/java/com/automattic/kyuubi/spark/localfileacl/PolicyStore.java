package com.automattic.kyuubi.spark.localfileacl;

import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Holds the atomically published {@link AclState} and refreshes it with a digest-based,
 * non-blocking interval reload. Request threads never block on a reload in progress; they keep
 * using the currently published immutable state.
 */
public final class PolicyStore {

  private static final Logger LOG = LoggerFactory.getLogger(PolicyStore.class);

  private final Path aclFile;
  private final AclYamlLoader loader;
  private final Duration reloadInterval;

  /** Monotonic nanosecond source, so a backward wall-clock step cannot delay revocation. */
  private final LongSupplier ticker;

  private volatile AclState state;
  private final ReentrantLock reloadLock = new ReentrantLock();
  private volatile long nextCheckAtNanos;

  public PolicyStore(
      Path aclFile, AclYamlLoader loader, Duration reloadInterval, LongSupplier ticker) {
    this.aclFile = aclFile;
    this.loader = loader;
    this.reloadInterval = reloadInterval;
    this.ticker = ticker;
    this.nextCheckAtNanos = ticker.getAsLong() + reloadInterval.toNanos();
  }

  /** Loads the initial policy; throws if it is invalid so plugin initialization fails. */
  public void initialLoad() {
    reloadNow();
    if (state instanceof AclState.Invalid invalid) {
      throw new IllegalStateException("Initial ACL load failed: " + invalid.error());
    }
  }

  public AclState current() {
    return state;
  }

  /** Non-blocking: at most one request thread performs the reload once the interval elapses. */
  public void maybeReload() {
    if (ticker.getAsLong() - nextCheckAtNanos < 0) {
      return;
    }
    if (!reloadLock.tryLock()) {
      LOG.debug("ACL reload already in progress; continuing with the published state");
      return;
    }
    try {
      if (ticker.getAsLong() - nextCheckAtNanos < 0) {
        return;
      }
      reloadNow();
      nextCheckAtNanos = ticker.getAsLong() + reloadInterval.toNanos();
    } finally {
      reloadLock.unlock();
    }
  }

  private void reloadNow() {
    long startNanos = System.nanoTime();
    try {
      byte[] content = loader.readVerified(aclFile);
      String digest = sha256(content);
      if (state instanceof AclState.Valid valid
          && digest.equals(valid.digest())
          && !anyUnresolvedPathResolvable(valid.policy())) {
        LOG.debug("ACL digest unchanged ({}); skipping reparse", digest);
        return;
      }
      AclPolicy policy = loader.parse(content);
      state = new AclState.Valid(policy, digest);
      LOG.info(
          "Activated ACL policy from {}: {} users, {} groups, {} rules, {} unresolved, "
              + "digest {}, {} ms",
          aclFile,
          policy.userRules().size(),
          policy.groupRules().size(),
          policy.ruleCount(),
          policy.unresolvedPaths().size(),
          digest,
          (System.nanoTime() - startNanos) / 1_000_000);
    } catch (Exception e) {
      state = new AclState.Invalid(e.getMessage());
      LOG.warn(
          "ACL policy at {} is invalid; local resources will be rejected until a valid "
              + "policy is installed",
          aclFile,
          e);
    }
  }

  /**
   * An exact rule omitted for a missing file must activate once that file appears, even though the
   * ACL content — and therefore its digest — never changed. Only a full reparse canonicalizes the
   * path and re-runs the policy checks, so the digest fast path must yield here.
   *
   * <p>The probe mirrors the loader's rule that absence alone is tolerable: it resolves each path
   * exactly as the loader would, and only {@link NoSuchFileException} keeps the fast path. Any
   * other I/O failure (an inaccessible parent, a symlink loop) forces the reparse, which then
   * invalidates the policy — {@code Files.exists} would report all of those as "still missing" and
   * silently keep serving a policy the loader would have rejected.
   */
  private static boolean anyUnresolvedPathResolvable(AclPolicy policy) {
    for (Path unresolved : policy.unresolvedPaths()) {
      try {
        unresolved.toRealPath();
        return true;
      } catch (NoSuchFileException e) {
        // Still absent: the omitted rule stays omitted, with no reparse and no ERROR churn.
      } catch (IOException e) {
        return true;
      }
    }
    return false;
  }

  private static String sha256(byte[] content) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
  }
}
