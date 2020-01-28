package com.softwareplumbers.keymanager;

import java.io.File;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.stream.Stream;

import org.junit.After;
import org.junit.Assert;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.ImportResource;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@ImportResource({"classpath*:services.xml"})
@EnableConfigurationProperties
public class KeyManagerTest {
    
    private Path file;
    private Path folder;
    
    @Autowired
    private ApplicationContext springContext;
    
    @Before
    public void setup() throws IOException {
        String tmpDir = System.getProperty("java.io.tmpdir");
        file = FileSystems.getDefault().getPath(tmpDir, "Doctane_TEST.keystore");
        folder = FileSystems.getDefault().getPath(tmpDir, "Doctane_TEST_exports");
        Files.createDirectories(folder);
    }
    
    @After 
    public void cleanup() throws IOException {
        file.toFile().delete();
        Files.list(folder).forEach(path -> path.toFile().delete());
        folder.toFile().delete();
    }
    
    @Test
    public void testCreateNewKeyStore() throws KeyStoreException, IOException {
        KeyManager<TestSecretKey,TestKeyPair> kmgr = new KeyManager<>(file.toString(), "password", TestSecretKey.class, TestKeyPair.class);
        Key key = kmgr.getKey(TestSecretKey.MySecretKeyA);
        assertNotNull(key);
    }
    
    @Test
    public void testCreateNewKeyStoreWithPublish() throws KeyStoreException, IOException, CertificateEncodingException {
        KeyManager<TestSecretKey,TestKeyPair> kmgr = new KeyManager<>(file.toString(), folder.toString(), "password", TestSecretKey.class, TestKeyPair.class);
        X509Certificate cert = kmgr.getCertificate(TestKeyPair.KeyPairA);
        String name = cert.getSubjectDN().getName() + ".der";
        Path certPath = folder.resolve(name);
        assertTrue(Files.exists(certPath));
        byte[] content = Base64.getUrlDecoder().decode(Files.readAllBytes(certPath));
        assertArrayEquals(cert.getEncoded(), content);        
    }
    
    @Test
    public void testCreateNewKeyStoreWithImport() throws KeyStoreException, IOException, CertificateEncodingException, BadKeyException, InitializationFailure {
        KeyManager<TestSecretKey,TestKeyPair> kmgr = new KeyManager<>(file.toString(), folder.toString(), "password", TestSecretKey.class, TestKeyPair.class);
        X509Certificate cert = kmgr.getCertificate(TestKeyPair.KeyPairA);
        String name = cert.getSubjectDN().getName();
        // The cert should have been re-imported under its CN (a UUID)
        X509Certificate cert2 = kmgr.getCertificate(name);
        assertEquals(cert, cert2);
    }
    
    @Test
    public void testPersistentStore() throws KeyStoreException, IOException {
        KeyManager<TestSecretKey,TestKeyPair> kmgr1 = new KeyManager<>(file.toString(), "password", TestSecretKey.class, TestKeyPair.class);
        Key key1 = kmgr1.getKey(TestSecretKey.MySecretKeyA);
        KeyManager<TestSecretKey,TestKeyPair> kmgr2 = new KeyManager<>(file.toString(), "password", TestSecretKey.class, TestKeyPair.class);
        Key key2 = kmgr2.getKey(TestSecretKey.MySecretKeyA);
        assertEquals(key1,key2);
    }
    
    @Test
    public void testKeyManagerAsSpringBean() throws BadKeyException, InitializationFailure {
        KeyManager<?,?> kmgr = springContext.getBean("keymgr", KeyManager.class);
        Key key = kmgr.getKey(TestSecretKey.MySecretKeyA.name());
        assertNotNull(key);
    }
}


