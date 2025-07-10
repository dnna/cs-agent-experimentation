package com.example;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.logging.Logger;
import java.io.PrintWriter;

public class SensitiveDataExposure {
    
    private static final Logger logger = Logger.getLogger(SensitiveDataExposure.class.getName());
    
    // CWE-200: Information disclosure via logging
    public void loginUser(String username, String password) {
        logger.info("User login attempt: " + username + " with password: " + password);
        if (authenticateUser(username, password)) {
            logger.info("Login successful for user: " + username);
        } else {
            logger.warning("Login failed for user: " + username + " password: " + password);
        }
    }
    
    // CWE-200: Sensitive data in error messages
    public void handleError(HttpServletRequest request, HttpServletResponse response) throws Exception {
        try {
            String query = "SELECT * FROM users WHERE id = " + request.getParameter("id");
            // Database operation
        } catch (Exception e) {
            PrintWriter out = response.getWriter();
            out.println("Database error: " + e.getMessage());
            out.println("Stack trace: " + e.getStackTrace());
        }
    }
    
    // CWE-200: Hardcoded sensitive information
    public void connectToDatabase() {
        String dbUrl = "jdbc:mysql://localhost:3306/mydb";
        String dbUser = "root";
        String dbPassword = "admin123";
        String apiKey = "sk-1234567890abcdef";
        // Use credentials
    }
    
    private boolean authenticateUser(String username, String password) {
        return false;
    }
}