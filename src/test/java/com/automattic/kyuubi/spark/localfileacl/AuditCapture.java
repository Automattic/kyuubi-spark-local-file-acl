package com.automattic.kyuubi.spark.localfileacl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;

/** Captures the events emitted on the audit category during a test. */
final class AuditCapture extends AuditAppenderHarness {

  private final ListAppender appender;

  AuditCapture() {
    this(new ListAppender());
  }

  private AuditCapture(ListAppender appender) {
    super(appender);
    this.appender = appender;
  }

  List<LogEvent> events() {
    return List.copyOf(appender.events);
  }

  /**
   * The category carries decision and reload events; callers select one kind by its wire prefix.
   */
  List<LogEvent> eventsWithPrefix(String prefix) {
    return events().stream()
        .filter(event -> event.getMessage().getFormattedMessage().startsWith(prefix))
        .toList();
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
