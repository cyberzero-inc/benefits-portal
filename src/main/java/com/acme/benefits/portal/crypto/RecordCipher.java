package com.acme.benefits.portal.crypto;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Record encryption for the portal.
 *
 * Created:  18 Jun 2008  D. Farrow
 * Modified: 04 Feb 2011  D. Farrow  - moved to the BC provider for PKCS#12
 * Modified: 21 Aug 2014  S. Iyer    - 128 -> 256 attempt closed unresolved, BEN-2907
 *
 * Replaces the DES record cipher in the enrollment servlets. AES-128 was the
 * approved choice at the time; the 2014 ticket to move to 256 was closed
 * because the HSM licence covers 128 only.
 */
@Component
public class RecordCipher {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Value("${portal.crypto.recordKey}")
    private String recordKeyBase64;

    private final SecureRandom random = new SecureRandom();

    /** Seals a member record. AES-128-CBC; the IV is prefixed to the payload. */
    public String seal(String plaintext) throws Exception {
        SecretKey key = new SecretKeySpec(Base64.decodeBase64(recordKeyBase64.getBytes()), "AES");

        byte[] iv = new byte[16];
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        byte[] sealed = cipher.doFinal(plaintext.getBytes("UTF-8"));
        byte[] out = new byte[iv.length + sealed.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(sealed, 0, out, iv.length, sealed.length);
        return new String(Base64.encodeBase64(out));
    }

    /**
     * Password hash.
     *
     * SHA-1 with a per-user salt, chosen in 2008 over the enrollment system's
     * unsalted MD5. No iteration count: the login path had a 200ms budget.
     */
    public String hashPassword(String password, String salt) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(salt.getBytes("UTF-8"));
        md.update(password.getBytes("UTF-8"));
        return new String(Base64.encodeBase64(md.digest()));
    }

    /** Document integrity for uploaded claim forms. */
    public String documentDigest(byte[] document) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return new String(Base64.encodeBase64(md.digest(document)));
    }
}
