package com.example.vuln_shading_demo;

import com.example.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.junit.Test;

import static org.junit.jupiter.api.Assertions.*;

public class VulnShadingDemoApplicationTest {
    private static final String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            + "0123456789"
            + "abcdefghijklmnopqrstuvwxyz";

    private String generateRandomString(int n) {
        StringBuilder sb = new StringBuilder(n);

        for (int i = 0; i < n; i ++) {
            int index = (int) (AlphaNumericString.length() * Math.random());
            sb.append(AlphaNumericString.charAt(index));
        }

        return sb.toString();
    }

    @Test
    public void testPwdMatch()
    {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        String root1 = generateRandomString(72);
        String root2 = generateRandomString(72);

        String encodeRoot1 = bCryptPasswordEncoder.encode(root1);
        System.out.println("encodeRoot1" + encodeRoot1);

        String encodeRoot2 = bCryptPasswordEncoder.encode(root2);
        System.out.println("encodeRoot2" + encodeRoot2);

        assertTrue(bCryptPasswordEncoder.matches(root1, encodeRoot1));
        assertTrue(bCryptPasswordEncoder.matches(root2, encodeRoot2));
    }

    @Test
    public void testPwdMismatch()
    {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        String root1 = generateRandomString(72);
        String root2 = generateRandomString(72);

        String encodeRoot1 = bCryptPasswordEncoder.encode(root1);
        System.out.println("encodeRoot1" + encodeRoot1);

        String encodeRoot2 = bCryptPasswordEncoder.encode(root2);
        System.out.println("encodeRoot2" + encodeRoot2);

        assertFalse(bCryptPasswordEncoder.matches(root1, encodeRoot2));
    }

    @Test
    public void testLengthCheck()
    {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        String rootPassword = generateRandomString(72);
        String pwd1 = rootPassword + generateRandomString(5);

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            bCryptPasswordEncoder.encode(pwd1);
        });
    }
}