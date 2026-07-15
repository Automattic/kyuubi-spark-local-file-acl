package com.automattic.kyuubi.spark.localfileacl;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;

/**
 * Attaches an {@link AbstractAppender} to the dedicated audit category (non-additive, so records do
 * not also reach the console) for the lifetime of the harness, and detaches it — both the logger
 * and the appender — on {@link #close()}. Subclasses supply the appender and whatever it does with
 * events.
 */
abstract class AuditAppenderHarness implements AutoCloseable {

  private final AbstractAppender appender;

  AuditAppenderHarness(AbstractAppender appender) {
    this.appender = appender;
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
}
