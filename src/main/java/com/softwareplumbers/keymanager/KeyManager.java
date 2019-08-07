package com.softwareplumbers.keymanager;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
import java.security.NoSuchProviderException;
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
import java.util.Optional;
import java.util.logging.Level;

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
 * Given two enumerations of keys and key pairs, KeyManager tries to ensure that keys exist for all
 * the specified keys, creating them if they do not already exist in the underlying key store.
 * 
 * Note the paired getKey and getKeyPair methods, which take either a string or enumeration argument.
 * The versions taking a string argument may throw a BadKeyException if the expected key/key pair does
 * not exist. The versions taking an enum argument should always, in principle, return a valid key.
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
    
    private Class<RequiredSecretKeys> requiredSecretKeys;
    private Class<RequiredKeyPairs> requiredKeyPairs;
    
    private String location, password;
    
    private Optional<KeyStore> keystore = Optional.empty(); 
    
    private KeyStore getKeyStore() throws InitializationFailure {
        if (!keystore.isPresent()) {
            try {
                keystore = Optional.of(load(location, password, requiredSecretKeys, requiredKeyPairs));
            } catch (IOException | KeyStoreException | NoSuchAlgorithmException | NoSuchProviderException | CertificateException | OperatorCreationException e) {
                throw new InitializationFailure("could not initialize keystore on path " + location, e);
            }
        }
        return keystore.get();
    }
    
    /** Generate a self-signed certificate for a given name and public/private key pair.
     * 
     * @param account The common name for the certificate
     * @param pair A public/private key pair
     * @return A self-signed X509 Certificate with 3 years of validity
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
     * Ensures a key store contains mandatory keys and key pairs. 
     * 
     * For each item in the given key enum, the key store will contain a randomly-generated
     * secret signing key
     * 
     * For each item in the given key pair enum, the key store will contain 
     * a randomly generated public/private key pair.
     * 
     * Existing keys in the key store are not updated.
     * 
     * @param keystore Key store
     * @param keys Mandatory public or secret keys in keystore
     * @param keyPairs Mandatory public/private key pairs in keystore
     */
    private static <Keys extends Enum<Keys>, KeyPairs extends Enum<KeyPairs>> boolean init(KeyStore keystore, Class<Keys> keys, Class<KeyPairs> keyPairs) throws NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, CertIOException, OperatorCreationException, CertificateException {
        LOG.trace("entering init with ({},{},{})", "<keystore>", keys, keyPairs );
        boolean updated = false;

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
                keystore.setKeyEntry(keypair.name(), (Key) kp.getPrivate(), KEY_PASSWORD.getPassword(), certChain);
                updated = true;
            }
        }
      
        LOG.trace("init exiting with {}", updated);
        return updated; 
    }
    
    private static <Keys extends Enum<Keys>, KeyPairs extends Enum<KeyPairs>> KeyStore load(
        String location, 
        String password, 
        Class<Keys> keys,
        Class<KeyPairs> keyPairs) throws 
        FileNotFoundException, 
        IOException, 
        NoSuchAlgorithmException, 
        CertificateException, 
        KeyStoreException, 
        NoSuchProviderException, 
        CertIOException, 
        OperatorCreationException {
        File file = new File(location);
        KeyStore keystore = KeyStore.getInstance("JCEKS");

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
        
        return keystore;
    }

    /** Set location of keystore
     * 
     * @param location 
     */
    public void setLocation(String location) { 
        this.location = location; 
        keystore = Optional.empty(); 
    }
    
    /** Set password of keystore
     * 
     * @param location 
     */
    public void setPassword(String password) {      
        this.password = password; 
        keystore = Optional.empty(); 
    }
    
    public void setRequiredSecretKeys(Class<RequiredSecretKeys> requiredSecretKeys) { 
        this.requiredSecretKeys = requiredSecretKeys; 
        keystore = Optional.empty(); 
    }
    
    public void setRequiredKeyPairs(Class<RequiredKeyPairs> requiredKeyPairs) { 
        this.requiredKeyPairs = requiredKeyPairs; 
        keystore = Optional.empty(); 
    }
    
    /** Get a key from the key store.
     * 
     * @param name the key alias
     * @return The associated key
     * @throws BadKeyException if the given key cannot be found
     * @throws InitializationFailure if keystore cannot be initialized
     */
    public Key getKey(String name) throws BadKeyException, InitializationFailure {
        LOG.trace("entering getKey with {}", name);
        try {
            if (getKeyStore().isCertificateEntry(name)) {
                Certificate cert = getKeyStore().getCertificate(name);
                return cert.getPublicKey();
            } else {
                Key key = getKeyStore().getKey(name, KEY_PASSWORD.getPassword());
                if (key instanceof PrivateKey) {
                    Certificate cert = getKeyStore().getCertificate(name);
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
    
    /** Get a key pair from the key store.
     * 
     * @param name the key alias
     * @return The associated key pair
     * @throws BadKeyException if the given key pair cannot be found
     */
    public KeyPair getKeyPair(String name) throws BadKeyException, InitializationFailure {
        LOG.trace("entering getKeyPair with {}", name);
        try {
            Key key = getKeyStore().getKey(name, KEY_PASSWORD.getPassword());
            Certificate cert = getKeyStore().getCertificate(name);
            LOG.trace("getKeyPair returns", "<redacted>");
            return new KeyPair(cert.getPublicKey(), (PrivateKey)key);
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            LOG.debug("getKeyPair rethrows {}", e);
            throw new BadKeyException(e);
        } 
        
    }
  
    /** Get a key pair from the key store.
     * 
     * @param name the key alias
     * @return The associated key pair
     * @throws BadKeyException if the given key pair cannot be found
     */
    public KeyPair getKeyPair(RequiredKeyPairs name) {
    	try {
    		return getKeyPair(name.name());
    	} catch (BadKeyException e) {
    		throw new RuntimeException(e.getCause());
    	} catch (InitializationFailure e) {
            throw new RuntimeException(e.getCause());
        }
    }
    
    /** Get a key from the key store.
     * 
     * @param keyname the key alias
     * @return The associated key
     */
    public Key getKey(RequiredSecretKeys keyname) {
    	try {
    		return getKey(keyname.name());
    	} catch (BadKeyException e) {
    		throw new RuntimeException(e.getCause());
    	} catch (InitializationFailure e) {
            throw new RuntimeException(e.getCause());
        }
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
        this.location = location;
        this.password = password;
        this.requiredKeyPairs = keyPairs;
        this.requiredSecretKeys = keys;
        LOG.trace("exiting constructor");
    }

    public KeyManager() throws KeyStoreException {
        this("/tmp", "password", null, null);
    }
}
