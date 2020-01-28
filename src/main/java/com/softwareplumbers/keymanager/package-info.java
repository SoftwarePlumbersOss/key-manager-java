/** Key Manager looks after the keys needed by an application.
 * 
 * Given two enumerations of keys and key pairs, KeyManager tries to ensure that keys exist for all
 * the specified keys, creating them if they do not already exist in the underlying key store.
 * 
 * While this might seem a little obscure, it is very useful when working with multiple components 
 * of a distributed application. Maintenance activity is confined to copying public keys between
 * key stores, without requiring manual creation of keys.
 * 
 * To this end, KeyManager will export any public keys it creates as base 64 encoded DER files to
 * a supplied location. It will also import any public keys found in this location. Thus, in 
 * development mode, a number of components sharing the same key manager import/export directory
 * will 'just work' in the sense that private keys will be automatically generated and public
 * keys will be automatically exported and imported.
 * 
 */
package com.softwareplumbers.keymanager;
