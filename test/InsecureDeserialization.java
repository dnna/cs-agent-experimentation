package com.example;

import javax.servlet.http.HttpServletRequest;
import java.io.*;

public class InsecureDeserialization {
    
    // CWE-502: Deserialization of untrusted data
    public Object deserializeUserInput(HttpServletRequest request) throws IOException, ClassNotFoundException {
        String serializedData = request.getParameter("data");
        byte[] data = serializedData.getBytes();
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return ois.readObject();
    }
    
    // CWE-502: Unsafe deserialization from file
    public Object loadFromFile(String filename) throws IOException, ClassNotFoundException {
        FileInputStream fis = new FileInputStream(filename);
        ObjectInputStream ois = new ObjectInputStream(fis);
        return ois.readObject();
    }
    
    // CWE-502: Deserialization with custom class loader
    public Object deserializeWithClassLoader(byte[] data) throws IOException, ClassNotFoundException {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return ois.readObject();
    }
}