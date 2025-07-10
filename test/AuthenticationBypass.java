package com.example;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class AuthenticationBypass {
    
    // CWE-287: Improper Authentication - Hardcoded credentials
    public boolean authenticateUser(String username, String password) {
        if ("admin".equals(username) && "password123".equals(password)) {
            return true;
        }
        return false;
    }
    
    // CWE-287: Authentication bypass via parameter manipulation
    public boolean isUserAuthorized(HttpServletRequest request) {
        String isAdmin = request.getParameter("isAdmin");
        if ("true".equals(isAdmin)) {
            return true;
        }
        return false;
    }
    
    // CWE-384: Session fixation vulnerability
    public void login(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession();
        String username = request.getParameter("username");
        // Session ID not regenerated after login
        session.setAttribute("authenticated", true);
        session.setAttribute("username", username);
    }
}