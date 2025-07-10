package com.example;

import javax.servlet.http.HttpServletRequest;
import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.NamingException;
import java.util.Hashtable;

public class LdapInjection {
    
    // CWE-90: LDAP Injection via search filter
    public void searchUser(HttpServletRequest request) throws NamingException {
        String username = request.getParameter("username");
        String filter = "(&(objectClass=person)(uid=" + username + "))";
        
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");
        
        DirContext ctx = new InitialDirContext(env);
        ctx.search("ou=users,dc=example,dc=com", filter, null);
    }
    
    // CWE-90: LDAP Injection in authentication
    public boolean authenticateUser(String username, String password) throws NamingException {
        String filter = "(&(objectClass=person)(uid=" + username + ")(userPassword=" + password + "))";
        
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");
        
        DirContext ctx = new InitialDirContext(env);
        return ctx.search("ou=users,dc=example,dc=com", filter, null).hasMore();
    }
    
    // CWE-90: LDAP Injection in DN construction
    public void modifyUserAttribute(String username, String attribute) throws NamingException {
        String dn = "uid=" + username + ",ou=users,dc=example,dc=com";
        
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");
        
        DirContext ctx = new InitialDirContext(env);
        ctx.getAttributes(dn);
    }
}