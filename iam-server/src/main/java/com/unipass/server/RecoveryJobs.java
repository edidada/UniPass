package com.unipass.server;

import com.unipass.password.PasswordChangeService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.*;

@Configuration
@EnableScheduling
@ConditionalOnProperty(name="unipass.jobs.enabled",havingValue="true",matchIfMissing=true)
public class RecoveryJobs {
    private final RecoveryMailWorker mail;private final PasswordChangeService passwords;
    private final RedisSecurityState security;
    private static final org.slf4j.Logger LOG=org.slf4j.LoggerFactory.getLogger(RecoveryJobs.class);
    public RecoveryJobs(RecoveryMailWorker mail,PasswordChangeService passwords,RedisSecurityState security){this.mail=mail;this.passwords=passwords;this.security=security;}
    @Scheduled(fixedDelayString="${unipass.jobs.security-delay-ms:1000}") void security(){
        try{security.recoverIfNeeded();}catch(RuntimeException e){LOG.warn("Redis authentication recovery unavailable");}
    }
    @Scheduled(fixedDelayString="${unipass.jobs.recovery-delay-ms:5000}") void mail(){
        try{mail.runOnce();}catch(RuntimeException e){LOG.warn("Recovery mail worker state unavailable");}
    }
    @Scheduled(fixedDelayString="${unipass.jobs.recovery-delay-ms:5000}") void abandoned(){
        try{passwords.markAbandonedUnknown();}catch(RuntimeException e){LOG.warn("Password recovery scan unavailable");}
    }
}
