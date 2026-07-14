package com.automattic.kyuubi.spark.localfileacl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;

/**
 * Attaches an in-memory appender to the dedicated audit category (non-additive, so records never
 * reach the console) and collects the emitted events. Kyuubi's logging backend is Log4j2, which is
 * what an operator routes this category with.
 */
final class AuditCapture implements AutoCloseable {

  private final ListAppender appender = new ListAppender();

  AuditCapture() {
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
    context.getConfiguration().removeLogger(AuditLog.LOGGER_NAME);
    context.updateLoggers();
    appender.stop();
  }

  List<LogEvent> events() {
    return List.copyOf(appender.events);
  }

  LogEvent onlyEvent() {
    List<LogEvent> events = events();
    if (events.size() != 1) {
      throw new AssertionError("expected exactly one audit event but got " + messages());
    }
    return events.get(0);
  }

  List<String> messages() {
    return events().stream().map(event -> event.getMessage().getFormattedMessage()).toList();
  }

  String onlyMessage() {
    return onlyEvent().getMessage().getFormattedMessage();
  }

  private static final class ListAppender extends AbstractAppender {

    private final List<LogEvent> events = Collections.synchronizedList(new ArrayList<>());

    private ListAppender() {
      super("audit-capture", null, null, false, Property.EMPTY_ARRAY);
    }

    @Override
    public void append(LogEvent event) {
      events.add(event.toImmutable());
    }
  }
}
