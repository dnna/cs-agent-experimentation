package com.example;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;

public class AccessControlIssues {
    
    // CWE-284: Improper access control - Missing authorization check
    public void deleteUser(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        // No authorization check - any user can delete any user
        deleteUserFromDatabase(userId);
    }
    
    // CWE-284: Insecure direct object reference
    public void viewUserProfile(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String userId = request.getParameter("userId");
        // Direct access to user data without permission check
        String userData = getUserData(userId);
        response.getWriter().print(userData);
    }
    
    // CWE-284: Path traversal allowing access to unauthorized files
    public void downloadFile(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String filename = request.getParameter("filename");
        File file = new File("/secure/documents/" + filename);
        // No access control check on file access
        FileInputStream fis = new FileInputStream(file);
        // Stream file to response
    }
    
    // CWE-284: Privilege escalation via parameter manipulation
    public void updateUserRole(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        String newRole = request.getParameter("role");
        // No check if current user can modify roles
        updateUserRoleInDatabase(userId, newRole);
    }
    
    private void deleteUserFromDatabase(String userId) {}
    private String getUserData(String userId) { return "user data"; }
    private void updateUserRoleInDatabase(String userId, String role) {}
}