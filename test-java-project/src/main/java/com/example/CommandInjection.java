package com.example;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class CommandInjection {
    
    // CWE-78: Command Injection via Runtime.exec()
    public void executeCommand(HttpServletRequest request) throws IOException {
        String command = request.getParameter("cmd");
        Runtime.getRuntime().exec("ping " + command);
    }
    
    // CWE-78: Command Injection via ProcessBuilder
    public void runProcess(HttpServletRequest request) throws IOException {
        String filename = request.getParameter("file");
        ProcessBuilder pb = new ProcessBuilder("cat", "/var/log/" + filename);
        pb.start();
    }
    
    // CWE-78: Command Injection in shell command
    public void executeShellCommand(String userInput) throws IOException {
        String[] cmd = {"/bin/sh", "-c", "ls -la " + userInput};
        Runtime.getRuntime().exec(cmd);
    }
}