package com.softwareplumbers.keymanager;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStoreException;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class KeyStoreTest {
    
    Path file;
    
    @Before
    public void setup() {
        file = FileSystems.getDefault().getPath(System.getProperty("java.io.tmpdir"), "Doctane_TEST.keystore"); 
    }
    
    @After 
    public void cleanup() {
        file.toFile().delete();
    }
    
    @Test
    public void testCreateNewKeyStore() throws KeyStoreException, IOException {
        KeyManager<TestSecretKey,TestKeyPair> kmgr = new KeyManager<>(file.toString(), "password", TestSecretKey.class, TestKeyPair.class);
        Key key = kmgr.getKey(TestSecretKey.MySecretKeyA);
        assertNotNull(key);
    }
    
    @Test
    public void testPersistentStore() throws KeyStoreException, IOException {
        KeyManager<TestSecretKey,TestKeyPair> kmgr1 = new KeyManager<>(file.toString(), "password", TestSecretKey.class, TestKeyPair.class);
        Key key1 = kmgr1.getKey(TestSecretKey.MySecretKeyA);
        KeyManager<TestSecretKey,TestKeyPair> kmgr2 = new KeyManager<>(file.toString(), "password", TestSecretKey.class, TestKeyPair.class);
        Key key2 = kmgr2.getKey(TestSecretKey.MySecretKeyA);
        assertEquals(key1,key2);
    }
}


