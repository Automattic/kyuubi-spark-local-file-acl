package com.automattic.kyuubi.spark.localfileacl;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/**
 * Deterministic clock for reload tests. Wall time ({@link #instant()}) and the monotonic ticker
 * ({@link #nanos()}) are tracked independently so tests can simulate a backward wall-clock step
 * while monotonic time keeps advancing, like a real NTP adjustment.
 */
final class MutableClock extends Clock {

  private volatile Instant instant = Instant.parse("2026-01-01T00:00:00Z");
  private volatile long monotonicNanos = 0L;

  /** Advances both wall time and the monotonic ticker. */
  void advance(Duration duration) {
    if (duration.isNegative()) {
      throw new IllegalArgumentException("Use rewindWallClock to move wall time backwards");
    }
    instant = instant.plus(duration);
    monotonicNanos += duration.toNanos();
  }

  /** Steps wall time backwards without touching the monotonic ticker. */
  void rewindWallClock(Duration duration) {
    instant = instant.minus(duration);
  }

  /** Monotonic ticker for PolicyStore reload scheduling; never moves backwards. */
  long nanos() {
    return monotonicNanos;
  }

  @Override
  public ZoneId getZone() {
    return ZoneOffset.UTC;
  }

  @Override
  public Clock withZone(ZoneId zone) {
    return this;
  }

  @Override
  public Instant instant() {
    return instant;
  }
}
