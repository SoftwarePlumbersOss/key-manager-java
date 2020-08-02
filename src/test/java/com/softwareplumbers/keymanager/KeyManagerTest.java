package com.softwareplumbers.keymanager;

import com.softwareplumbers.keymanager.KeyManager.NO_KEYS;
import java.io.File;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Random;
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
    private Path file2;
    private Path folder;
    
    @Autowired
    private ApplicationContext springContext;
    
    @Before
    public void setup() throws IOException {
        String tmpDir = System.getProperty("java.io.tmpdir");
        file = FileSystems.getDefault().getPath(tmpDir, "Doctane_TEST.keystore");
        file2 = FileSystems.getDefault().getPath(tmpDir, "Doctane_TEST_2.keystore");
        folder = FileSystems.getDefault().getPath(tmpDir, "Doctane_TEST_exports");
        Files.createDirectories(folder);
    }
    
    @After 
    public void cleanup() throws IOException {
        file.toFile().delete();
        file2.toFile().delete();
        Files.list(folder).forEach(path -> path.toFile().delete());
        folder.toFile().delete();
    }
    
    private static String extractName(X509Certificate cert) {
        String dn = cert.getSubjectDN().getName();
        return (dn.startsWith("CN=") || dn.startsWith("cn=")) ? dn.substring(3) : dn; 
    }
    
    
    @Test
    public void testCreateNewKeyStore() throws KeyStoreException, IOException {
        KeyManager<TestSecretKey,TestKeyPair> kmgr = new KeyManager<>(file.toString(), folder.toString(), "password", TestSecretKey.class, TestKeyPair.class);
        Key key = kmgr.getKey(TestSecretKey.MySecretKeyA);
        assertNotNull(key);
    }
    
    @Test
    public void testCreateNewKeyStoreWithPublish() throws KeyStoreException, IOException, CertificateEncodingException {
        KeyManager<TestSecretKey,TestKeyPair> kmgr = new KeyManager<>(file.toString(), folder.toString(), "password", TestSecretKey.class, TestKeyPair.class);
        X509Certificate cert = kmgr.getCertificate(TestKeyPair.KeyPairA);
        String name = extractName(cert) + ".der";
        Path certPath = folder.resolve(name);
        assertTrue(Files.exists(certPath));
        byte[] content = Base64.getUrlDecoder().decode(Files.readAllBytes(certPath));
        assertArrayEquals(cert.getEncoded(), content);        
    }
    
    @Test
    public void testCreateNewKeyStoreWithImport() throws KeyStoreException, IOException, CertificateEncodingException, BadKeyException, InitializationFailure {
        KeyManager<TestSecretKey,TestKeyPair> kmgr = new KeyManager<>(file.toString(), folder.toString(), "password", TestSecretKey.class, TestKeyPair.class);
        X509Certificate cert = kmgr.getCertificate(TestKeyPair.KeyPairA);
        String name = extractName(cert);
        // The cert should have been re-imported under its CN
        X509Certificate cert2 = kmgr.getCertificate(name);
        assertEquals(cert, cert2);
    }
    
    @Test
    public void testPersistentStore() throws KeyStoreException, IOException {
        KeyManager<TestSecretKey,TestKeyPair> kmgr1 = new KeyManager<>(file.toString(), folder.toString(), "password", TestSecretKey.class, TestKeyPair.class);
        Key key1 = kmgr1.getKey(TestSecretKey.MySecretKeyA);
        KeyManager<TestSecretKey,TestKeyPair> kmgr2 = new KeyManager<>(file.toString(), folder.toString(), "password", TestSecretKey.class, TestKeyPair.class);
        Key key2 = kmgr2.getKey(TestSecretKey.MySecretKeyA);
        assertEquals(key1,key2);
    }
    
    @Test
    public void testKeyManagerAsSpringBean() throws BadKeyException, InitializationFailure {
        KeyManager<?,?> kmgr = springContext.getBean("keymgr", KeyManager.class);
        Key key = kmgr.getKey(TestSecretKey.MySecretKeyA.name());
        assertNotNull(key);
    }
    
    @Test
    public void testGetPublishedName() throws KeyStoreException, BadKeyException, InitializationFailure, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        KeyManager<NO_KEYS,TestKeyPair> kmgr = new KeyManager<>(file.toString(), folder.toString(), "password", NO_KEYS.class, TestKeyPair.class);
        assertEquals(kmgr.getPublishedName(TestKeyPair.KeyPairA), kmgr.getPublishedName("KeyPairA"));
    }

    @Test
    public void testSharedKeystoreMessageValidation() throws KeyStoreException, BadKeyException, InitializationFailure, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        KeyManager<NO_KEYS,TestKeyPair> kmgr = new KeyManager<>(file.toString(), folder.toString(), "password", NO_KEYS.class, TestKeyPair.class);
        PrivateKey pk = kmgr.getKeyPair(TestKeyPair.KeyPairA).getPrivate();
        Signature sig = Signature.getInstance(KeyManager.PUBLIC_KEY_SIGNATURE_ALGORITHM, "SUN");
        byte[] randomData = new byte[12];
        new Random().nextBytes(randomData);
        sig.initSign(pk);
        sig.update(randomData);
        byte[] signature = sig.sign();
        Certificate cert = kmgr.getCertificate(kmgr.getPublishedName(TestKeyPair.KeyPairA));
        Signature sigv = Signature.getInstance(KeyManager.PUBLIC_KEY_SIGNATURE_ALGORITHM, "SUN");
        sigv.initVerify(cert.getPublicKey());
        sigv.update(randomData);
        assertTrue(sigv.verify(signature));        
    }
    
    @Test
    public void testPublishedKeyMessageValidation() throws KeyStoreException, BadKeyException, InitializationFailure, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        // Creating the client keystore will automatically publish the public key to folder
        KeyManager<NO_KEYS,TestKeyPair> kmgrClient = new KeyManager<>(file.toString(), folder.toString(), "password", NO_KEYS.class, TestKeyPair.class);
        // Creating the server keytore will automatically import the public key from folder
        KeyManager<NO_KEYS,NO_KEYS> kmgrServer = new KeyManager<>(file2.toString(), folder.toString(), "password", NO_KEYS.class, NO_KEYS.class);
        PrivateKey pk = kmgrClient.getKeyPair(TestKeyPair.KeyPairA).getPrivate();
        Signature sig = Signature.getInstance(KeyManager.PUBLIC_KEY_SIGNATURE_ALGORITHM, "SUN");
        byte[] randomData = new byte[12];
        new Random().nextBytes(randomData);
        sig.initSign(pk);
        sig.update(randomData);
        byte[] signature = sig.sign();
        Certificate cert = kmgrServer.getCertificate(kmgrClient.getPublishedName(TestKeyPair.KeyPairA));
        Signature sigv = Signature.getInstance(KeyManager.PUBLIC_KEY_SIGNATURE_ALGORITHM, "SUN");
        sigv.initVerify(cert.getPublicKey());
        sigv.update(randomData);
        assertTrue(sigv.verify(signature));        
    }    

}


