package com.automattic.kyuubi.spark.localfileacl;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** Deterministic clock for reload-interval tests. */
final class MutableClock extends Clock {

  private volatile Instant instant = Instant.parse("2026-01-01T00:00:00Z");

  void advance(Duration duration) {
    instant = instant.plus(duration);
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
