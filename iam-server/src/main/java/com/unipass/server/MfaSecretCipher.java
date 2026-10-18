package com.unipass.server;

import javax.crypto.Cipher;
import javax.crypto.spec.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

/** Versioned AES-GCM envelope. AAD binds a factor secret to its immutable owner. */
final class MfaSecretCipher {
    private final SecretKeySpec key;
    MfaSecretCipher(String encodedKey) {
        byte[] raw=Base64.getDecoder().decode(encodedKey);
        try { if(raw.length!=32)throw new IllegalArgumentException("MFA key must contain 256 bits");key=new SecretKeySpec(raw,"AES"); }
        finally { Arrays.fill(raw,(byte)0); }
    }
    byte[] encrypt(UUID owner,byte[] secret) {
        byte[] iv=new byte[12];new SecureRandom().nextBytes(iv);
        byte[] payload=crypt(Cipher.ENCRYPT_MODE,owner,iv,secret);
        return ByteBuffer.allocate(1+iv.length+payload.length).put((byte)1).put(iv).put(payload).array();
    }
    byte[] decrypt(UUID owner,byte[] envelope) {
        if(envelope.length<29 || envelope[0]!=1)throw new IllegalStateException("Invalid factor envelope");
        return crypt(Cipher.DECRYPT_MODE,owner,Arrays.copyOfRange(envelope,1,13),Arrays.copyOfRange(envelope,13,envelope.length));
    }
    private byte[] crypt(int mode,UUID owner,byte[] iv,byte[] input) {
        try {
            Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(mode,key,new GCMParameterSpec(128,iv));
            cipher.updateAAD(("unipass:totp:v1:"+owner).getBytes(StandardCharsets.US_ASCII));return cipher.doFinal(input);
        } catch(Exception e) { throw new IllegalStateException("Factor key unavailable or ciphertext invalid"); }
    }
}
