package com.unipass.server;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Cross-instance election for the scheduled audit archiver. A PostgreSQL session-level advisory
 * lock is held on one pooled connection for the whole run, so only one node archives at a time; a
 * crashed node releases the lock when its connection closes. The lock is deliberately not tied to
 * the archive transaction: it guards mutual exclusion, while the archive itself keeps its own short
 * transaction and digest.
 */
@Component
public final class ArchiveElection {
  static final long LOCK_KEY = 0x41524348495645L; // "ARCHIVE"
  private final JdbcTemplate jdbc;

  public ArchiveElection(JdbcTemplate jdbc) {
    this.jdbc = jdbc;
  }

  /** Runs the task only if this process wins the advisory lock; returns whether it ran. */
  public boolean tryRun(Runnable task) {
    Boolean acquired =
        jdbc.execute(
            (ConnectionCallback<Boolean>)
                connection -> {
                  boolean locked;
                  try (PreparedStatement lock =
                      connection.prepareStatement("SELECT pg_try_advisory_lock(?)")) {
                    lock.setLong(1, LOCK_KEY);
                    try (ResultSet rows = lock.executeQuery()) {
                      locked = rows.next() && rows.getBoolean(1);
                    }
                  }
                  if (!locked) return false;
                  try {
                    task.run();
                    return true;
                  } finally {
                    try (PreparedStatement unlock =
                        connection.prepareStatement("SELECT pg_advisory_unlock(?)")) {
                      unlock.setLong(1, LOCK_KEY);
                      unlock.execute();
                    }
                  }
                });
    return Boolean.TRUE.equals(acquired);
  }
}
