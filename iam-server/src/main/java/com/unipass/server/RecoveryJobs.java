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
    private static final org.slf4j.Logger LOG=org.slf4j.LoggerFactory.getLogger(RecoveryJobs.class);
    public RecoveryJobs(RecoveryMailWorker mail,PasswordChangeService passwords){this.mail=mail;this.passwords=passwords;}
    @Scheduled(fixedDelayString="${unipass.jobs.recovery-delay-ms:5000}") void mail(){
        try{mail.runOnce();}catch(RuntimeException e){LOG.warn("Recovery mail worker state unavailable");}
    }
    @Scheduled(fixedDelayString="${unipass.jobs.recovery-delay-ms:5000}") void abandoned(){
        try{passwords.markAbandonedUnknown();}catch(RuntimeException e){LOG.warn("Password recovery scan unavailable");}
    }
}
