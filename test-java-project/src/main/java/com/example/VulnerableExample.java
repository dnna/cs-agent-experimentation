package com.example;

import java.sql.Connection;
import java.sql.Statement;
import java.sql.ResultSet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;

public class VulnerableExample {
    
    public void sqlInjectionVulnerable(HttpServletRequest request, Connection conn) throws Exception {
        String userId = request.getParameter("userId");
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE id = " + userId;
        ResultSet rs = stmt.executeQuery(query);
    }
    
    public void xssVulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String userInput = request.getParameter("input");
        response.getWriter().print("Hello " + userInput);
    }
    
    public void pathTraversalVulnerable(HttpServletRequest request) throws Exception {
        String fileName = request.getParameter("file");
        File file = new File("/uploads/" + fileName);
        // Process file
    }
}
