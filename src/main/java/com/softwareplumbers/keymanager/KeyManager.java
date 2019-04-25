package com.softwareplumbers.keymanager;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.KeyGenerator;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/** Key Manager
 * 
 * Manages both public/private key pairs and secret keys.
 * 
 * @author SWPNET\jonessex
 *
 * @param <RequiredSecretKeys> Enumeration of secret keys that must exist in the store (missing ones will be created)
 * @param <RequiredKeyPairs> Enumeration of public/private keys that must exist in the store (missing ones will be created)
 */
public class KeyManager<RequiredSecretKeys extends Enum<RequiredSecretKeys>, RequiredKeyPairs extends Enum<RequiredKeyPairs>> {
    
        
    public static final String PRIVATE_KEY_SIGNATURE_ALGORITHM = "HmacSHA256";
    public static final String PUBLIC_KEY_SIGNATURE_ALGORITHM = "SHA1withDSA";
    public static final String PUBLIC_KEY_TYPE = "DSA";
    
    private static final Provider BOUNCY_CASTLE = new BouncyCastleProvider();
    
    private static final KeyStore.PasswordProtection KEY_PASSWORD = new KeyStore.PasswordProtection("".toCharArray());
    
    private static final Logger LOG = LoggerFactory.getLogger(KeyManager.class);
    
    private KeyStore keystore; 
    
    /** Generate a certificate for the default service account.
     * 
     * This is really only for creating a runnable test setup.
     * 
     * @param subjectDN
     * @param pair
     * @return
     * @throws CertIOException
     * @throws OperatorCreationException
     * @throws CertificateException 
     */
    private static X509Certificate generateCertificate(String account, KeyPair pair) throws CertIOException, OperatorCreationException, CertificateException {

        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        X500Name dnName = new X500Name("cn=" + account);
        BigInteger certSerialNumber = new BigInteger(Long.toString(now)); // <-- Using the current timestamp as the certificate serial number

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 3); // <-- 3 Yr validity

        Date endDate = calendar.getTime();

        ContentSigner contentSigner = new JcaContentSignerBuilder(PUBLIC_KEY_SIGNATURE_ALGORITHM).build(pair.getPrivate());

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, pair.getPublic());

        // Extensions --------------------------

        // Basic Constraints
        BasicConstraints basicConstraints = new BasicConstraints(true); // <-- true for CA, false for EndEntity

        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints); // Basic Constraints is usually marked as critical.

        // -------------------------------------

        return new JcaX509CertificateConverter().setProvider(BOUNCY_CASTLE).getCertificate(certBuilder.build(contentSigner));
    }
    
    /** Initialize the key store.
     * 
     * Creates a new, default key store for the manager to use. It will contain a randomly-generated
     * secret signing key, and a randomly generated public/private key pair under the name 'defaultServiceAccount'.
     * 
     * The generated private key can be used to sign service requests passed to the auth/service endpoint, in order
     * to obtain an access token to use the API.
     * 
     * @param keystore
     */
    private static <Keys extends Enum<Keys>, KeyPairs extends Enum<KeyPairs>> boolean init(KeyStore keystore, Class<Keys> keys, Class<KeyPairs> keyPairs) {
        LOG.trace("entering init with ({},{},{})", "<keystore>", keys, keyPairs );
        boolean updated = false;
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");

            for (Keys key : keys.getEnumConstants()) {
                if (!keystore.containsAlias(key.name())) {
                    KeyGenerator generator = KeyGenerator.getInstance(PRIVATE_KEY_SIGNATURE_ALGORITHM, BOUNCY_CASTLE);
                    generator.init(256, random);
                    keystore.setKeyEntry(key.name(), generator.generateKey(), KEY_PASSWORD.getPassword(), null);
                    updated = true;
                }
            }


            for (KeyPairs keypair : keyPairs.getEnumConstants()) {
                if (!keystore.containsAlias(keypair.name())) {
                    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(PUBLIC_KEY_TYPE, BOUNCY_CASTLE);
                    keyGen.initialize(1024, random);
                    KeyPair kp = keyGen.generateKeyPair();
                    X509Certificate certificate = generateCertificate(keypair.name(), kp);  
                    Certificate[] certChain = new Certificate[1];  
                    certChain[0] = certificate;  
                    keystore.setKeyEntry(keypair.name(), (Key)kp.getPrivate(), KEY_PASSWORD.getPassword(), certChain);  
                    updated = true;
                }
            }
        } catch (Exception e) {
            LOG.debug("init rethrows {}", e);
            throw new RuntimeException(e);
            
        }         
        LOG.trace("init exiting with {}", updated);
        return updated; 
    }
    
    public Key getKey(String name) {
        LOG.trace("entering getKey with {}", name);
        try {
            if (keystore.isCertificateEntry(name)) {
                Certificate cert = keystore.getCertificate(name);
                return cert.getPublicKey();
            } else {
                Key key = keystore.getKey(name, KEY_PASSWORD.getPassword());
                if (key instanceof PrivateKey) {
                    Certificate cert = keystore.getCertificate(name);
                    key =  cert.getPublicKey();                    
                }
                LOG.trace("getKey returns", "<redacted>");
                return key;
            }
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            LOG.debug("getKey rethrows {}", e);
            throw new RuntimeException(e);
        } 
    }
    
    public KeyPair getKeyPair(String name) {
        LOG.trace("entering getKeyPair with {}", name);
        try {
            Key key = keystore.getKey(name, KEY_PASSWORD.getPassword());
            Certificate cert = keystore.getCertificate(name);
            LOG.trace("getKeyPair returns", "<redacted>");
            return new KeyPair(cert.getPublicKey(), (PrivateKey)key);
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            LOG.debug("getKeyPair rethrows {}", e);
            throw new RuntimeException(e);
        } 
        
    }
    
    public KeyPair getKeyPair(RequiredKeyPairs name) {
        return getKeyPair(name.name());
    }
    
    public Key getKey(RequiredSecretKeys keyname) {
        return getKey(keyname.name());
    }
    
    /** Create a Key Manager. 
     * 
     * @param location The location (Path) for the key store
     * @param password The password for the key store
     * @param keys An enumeration of secret key names to create in the key store
     * @param keyPairs An enumeration of public/private key pairs to create in the key store
     * @throws KeyStoreException
     */
    public KeyManager(String location, String password, Class<RequiredSecretKeys> keys, Class<RequiredKeyPairs> keyPairs) throws KeyStoreException {

        LOG.trace("entering constructor with ({},{})", location, "<redacted>");

        Security.addProvider(BOUNCY_CASTLE);

        File file = new File(location);
        keystore = KeyStore.getInstance("JCEKS");

        try {
            if (file.exists()) {
                try (InputStream is = new FileInputStream(file)) {
                    keystore.load(is, password.toCharArray());
                } 
            } else {
                keystore.load(null, password.toCharArray());
            }

            if (init(keystore, keys, keyPairs)) {
                try (OutputStream os = new FileOutputStream(file)) {
                    keystore.store(os, password.toCharArray());
                } 
            } 
        } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
            LOG.debug("constructor rethrows {}", e);
            throw new RuntimeException(e);
        }

        LOG.trace("exiting constructor");
    }

}
