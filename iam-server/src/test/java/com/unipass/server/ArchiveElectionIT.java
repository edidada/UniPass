package com.unipass.server;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/** Cross-instance election: a second caller must skip while the first holds the advisory lock. */
class ArchiveElectionIT {
    private EmbeddedPostgres pg;
    private HikariDataSource pool;
    private ArchiveElection election;

    @BeforeEach void start() throws Exception {
        System.setProperty("ot.epg.working-dir",
                Files.createDirectories(Path.of("target", "archive-election", "postgres")).toAbsolutePath().toString());
        pg = EmbeddedPostgres.builder().setPort(0).setServerConfig("listen_addresses", "127.0.0.1").start();
        pool = new HikariDataSource(new HikariConfig() {{
            setDataSource(pg.getPostgresDatabase());
            setMaximumPoolSize(4);
        }});
        election = new ArchiveElection(new JdbcTemplate(pool));
    }

    @AfterEach void stop() throws Exception {
        if (pool != null) pool.close();
        if (pg != null) pg.close();
    }

    @Test void onlyOneRunnerHoldsTheElectionAndItReleases() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread holder = new Thread(() -> {
            try {
                assertTrue(election.tryRun(() -> {
                    entered.countDown();
                    try { release.await(10, TimeUnit.SECONDS); }
                    catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
                }));
            } catch (Throwable problem) { failure.set(problem); }
        });
        holder.start();
        assertTrue(entered.await(10, TimeUnit.SECONDS), "first runner entered");
        AtomicBoolean secondRan = new AtomicBoolean();
        assertFalse(election.tryRun(() -> secondRan.set(true)), "second runner must skip while the lock is held");
        assertFalse(secondRan.get());
        release.countDown();
        holder.join(10_000);
        assertNull(failure.get());
        AtomicBoolean afterRelease = new AtomicBoolean();
        assertTrue(election.tryRun(() -> afterRelease.set(true)), "lock is reusable after release");
        assertTrue(afterRelease.get());
    }
}
