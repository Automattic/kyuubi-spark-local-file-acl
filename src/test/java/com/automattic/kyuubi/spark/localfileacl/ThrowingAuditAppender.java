package com.automattic.kyuubi.spark.localfileacl;

import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;

/**
 * Attaches an appender to the audit category that throws on every event, with {@code
 * ignoreExceptions=false} so the failure propagates to the caller — simulating a logging backend
 * that fails while the plugin emits an audit record.
 */
final class ThrowingAuditAppender extends AuditAppenderHarness {

  private ThrowingAuditAppender() {
    super(new Appender());
  }

  static ThrowingAuditAppender install() {
    return new ThrowingAuditAppender();
  }

  private static final class Appender extends AbstractAppender {

    private Appender() {
      // ignoreExceptions=false so the thrown error reaches the code emitting the event.
      super("throwing-audit", null, null, false, Property.EMPTY_ARRAY);
    }

    @Override
    public void append(LogEvent event) {
      throw new IllegalStateException("simulated audit backend failure");
    }
  }
}
