/** Key Manager looks after the keys needed by an application.
 * 
 * Given two enumerations of keys and key pairs, KeyManager tries to ensure that keys exist for all
 * the specified keys, creating them if they do not already exist in the underlying key store.
 * 
 * While this might seem a little obscure, it is very useful when working with multiple components 
 * of a distributed application. Maintenance activity is confined to copying public keys between
 * key stores, without requiring manual creation of keys.
 * 
 */
package com.softwareplumbers.keymanager;
