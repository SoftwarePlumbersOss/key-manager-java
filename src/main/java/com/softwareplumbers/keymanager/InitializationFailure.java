/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.softwareplumbers.keymanager;

/**
 *
 * @author jonathan.local
 */
public class InitializationFailure extends Exception {
    
    InitializationFailure(String msg, Exception cause) {
        super(msg, cause);
    }
    
}
