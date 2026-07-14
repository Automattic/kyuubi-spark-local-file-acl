package com.automattic.kyuubi.spark.localfileacl;

import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

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
  /** Audit timestamps only; reload scheduling uses the monotonic ticker below. */
  private final Clock clock;
  /** Monotonic nanosecond source, so a backward wall-clock step cannot delay revocation. */
  private final java.util.function.LongSupplier ticker;

  private final AtomicReference<AclState> state = new AtomicReference<>();
  private final ReentrantLock reloadLock = new ReentrantLock();
  private volatile long nextCheckAtNanos;
  private volatile String lastDigest;

  public PolicyStore(
      Path aclFile,
      AclYamlLoader loader,
      Duration reloadInterval,
      Clock clock,
      java.util.function.LongSupplier ticker) {
    this.aclFile = aclFile;
    this.loader = loader;
    this.reloadInterval = reloadInterval;
    this.clock = clock;
    this.ticker = ticker;
    this.nextCheckAtNanos = ticker.getAsLong() + reloadInterval.toNanos();
  }

  /** Loads the initial policy; throws if it is invalid so plugin initialization fails. */
  public void initialLoad() {
    reloadNow();
    if (state.get() instanceof AclState.Invalid invalid) {
      throw new IllegalStateException("Initial ACL load failed: " + invalid.error());
    }
  }

  public AclState current() {
    return state.get();
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
      if (digest.equals(lastDigest) && state.get() instanceof AclState.Valid) {
        LOG.debug("ACL digest unchanged ({}); skipping reparse", digest);
        return;
      }
      AclPolicy policy = loader.parse(content);
      state.set(new AclState.Valid(policy, digest, clock.instant()));
      lastDigest = digest;
      LOG.info("Activated ACL policy from {}: {} users, {} groups, {} rules, digest {}, {} ms",
          aclFile, policy.userRules().size(), policy.groupRules().size(), policy.ruleCount(),
          digest, (System.nanoTime() - startNanos) / 1_000_000);
    } catch (Exception e) {
      lastDigest = null;
      state.set(new AclState.Invalid(e.getMessage(), clock.instant()));
      LOG.warn("ACL policy at {} is invalid; local resources will be rejected until a valid "
          + "policy is installed", aclFile, e);
    }
  }

  private static String sha256(byte[] content) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
  }
}
