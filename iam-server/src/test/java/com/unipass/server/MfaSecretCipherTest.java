package com.unipass.server;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class MfaSecretCipherTest {
    @Test void secretEnvelopeAuthenticatesItsOwnerAndRejectsTampering() {
        var cipher=new MfaSecretCipher(Base64.getEncoder().encodeToString(new byte[32]));
        UUID owner=UUID.randomUUID();byte[] raw=new byte[20];new java.security.SecureRandom().nextBytes(raw);
        byte[] encrypted=cipher.encrypt(owner,raw);
        assertFalse(Arrays.equals(raw,encrypted));assertArrayEquals(raw,cipher.decrypt(owner,encrypted));
        assertThrows(IllegalStateException.class,()->cipher.decrypt(UUID.randomUUID(),encrypted));
        encrypted[encrypted.length-1]^=1;assertThrows(IllegalStateException.class,()->cipher.decrypt(owner,encrypted));
        assertThrows(IllegalArgumentException.class,()->new MfaSecretCipher(Base64.getEncoder().encodeToString(new byte[16])));
    }
}
