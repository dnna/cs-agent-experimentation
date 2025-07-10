package com.example;

import javax.servlet.http.HttpServletRequest;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class VulnerableComponents {
    
    // CWE-1104: Use of unmaintained third-party components
    // This simulates vulnerable dependency usage
    public void processUploadedFile(HttpServletRequest request) throws Exception {
        String filename = request.getParameter("filename");
        
        // Simulating vulnerable Apache Commons FileUpload usage
        FileInputStream fis = new FileInputStream(filename);
        
        // Zip slip vulnerability - CWE-22
        ZipInputStream zis = new ZipInputStream(fis);
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            String entryName = entry.getName();
            // Vulnerable: No path validation
            java.io.File file = new java.io.File("/uploads/" + entryName);
            file.createNewFile();
        }
    }
    
    // CWE-502: Deserializing data from uploaded files
    public Object deserializeUploadedObject(String filename) throws Exception {
        FileInputStream fis = new FileInputStream(filename);
        ObjectInputStream ois = new ObjectInputStream(fis);
        return ois.readObject();
    }
    
    // CWE-611: XML parsing with external entities enabled
    public void parseUploadedXml(String xmlFile) throws Exception {
        javax.xml.parsers.DocumentBuilderFactory factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        // Vulnerable: External entities enabled by default
        javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(new java.io.File(xmlFile));
    }
    
    // CWE-94: Code injection via dynamic class loading
    public void loadDynamicClass(HttpServletRequest request) throws Exception {
        String className = request.getParameter("class");
        Class<?> clazz = Class.forName(className);
        Object instance = clazz.newInstance();
    }
}