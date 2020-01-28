# key-manager

Key manager is a simple wrapper around a java keystore. If the key store does not exist, it is created. Simple configuration provides for the automatic creation of default keys.

## Usage

Suppose we have:

```
enum KeyPairs { MYAPP_CLIENT_KEY };
enum Keys { MYAPP_SIGNING_KEY };

KeyManager<Keys,KeyPairs> keyManager = new KeyManager<>(
	"/usr/local/myapp/keystore.jks", 
    "/usr/local/myapp/certs",
	"changeme", 
	Keys.class, 
	KeyParis.class
);
```

* If a keystore exists at /usr/local/myapp/keystore.jks, it will be loaded, if not it will be created and loaded
* The loaded key store will be checked for a KeyPair MYAPP_CLIENT_KEY and a Key MYAPP_SIGNING_KEY
* If these keys do not exist, they will be created. 
* Any certificates for any generated public keys will be exported with a random CN to /usr/local/myapp/certs
* Any certificates present in /usr/local/myapp/certs will be imported under an alias equal to the CN of the cert 

The keys can be accessed with:

```
Key mykey = keyMangager.getKey(Keys.MYAPP_SIGNING_KEY);
KeyPair myPayPair = keyManager.getKeyPair(KeyPairs.MYAPP_CLIENT_KEY);
Certificate myCeret = keyManager.getCertificate(KeyPairs.MYAPP_CLIENT_KEY);
```

Other keys which exist in the key store, but are not defined in the enums, can be accessed with:

```
Key myOtherKey = keyManager.getKey("SOME_OTHER_KEY");
```