package com.automattic.kyuubi.spark.localfileacl;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;

/**
 * Attaches an appender to the audit category that throws on every event, with {@code
 * ignoreExceptions=false} so the failure propagates to the caller — simulating a logging backend
 * that fails while the plugin emits an audit record.
 */
final class ThrowingAuditAppender implements AutoCloseable {

  private final Appender appender = new Appender();

  static ThrowingAuditAppender install() {
    return new ThrowingAuditAppender();
  }

  private ThrowingAuditAppender() {
    appender.start();
    LoggerContext context = (LoggerContext) LogManager.getContext(false);
    Configuration configuration = context.getConfiguration();
    configuration.addAppender(appender);
    LoggerConfig loggerConfig = new LoggerConfig(AuditLog.LOGGER_NAME, Level.ALL, false);
    loggerConfig.addAppender(appender, Level.ALL, null);
    configuration.addLogger(AuditLog.LOGGER_NAME, loggerConfig);
    context.updateLoggers();
  }

  @Override
  public void close() {
    LoggerContext context = (LoggerContext) LogManager.getContext(false);
    Configuration configuration = context.getConfiguration();
    configuration.removeLogger(AuditLog.LOGGER_NAME);
    configuration.getAppenders().remove(appender.getName());
    context.updateLoggers();
    appender.stop();
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
