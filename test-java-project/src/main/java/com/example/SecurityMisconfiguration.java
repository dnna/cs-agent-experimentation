package com.example;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class SecurityMisconfiguration {
    
    // CWE-16: Weak cryptographic algorithm
    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return new String(hash);
    }
    
    // CWE-330: Weak random number generation
    public String generateToken() {
        java.util.Random random = new java.util.Random();
        return String.valueOf(random.nextInt());
    }
    
    // CWE-614: Sensitive cookie without secure flag
    public void createSession(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession();
        session.setAttribute("authenticated", true);
        // Cookie sent without secure flag
        javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("sessionId", session.getId());
        cookie.setHttpOnly(false);
        cookie.setSecure(false);
        response.addCookie(cookie);
    }
    
    // CWE-295: Certificate validation disabled
    public void disableCertificateValidation() {
        System.setProperty("com.sun.net.ssl.checkRevocation", "false");
        System.setProperty("sun.security.ssl.allowUnsafeRenegotiation", "true");
    }
    
    // CWE-326: Weak encryption algorithm
    public void weakEncryption(String data) throws Exception {
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("DES");
        // DES is weak encryption
    }
}