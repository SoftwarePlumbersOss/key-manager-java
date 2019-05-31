package com.softwareplumbers.keymanager;

public class BadKeyException extends Exception {

	BadKeyException(Exception e) {
		super(e);
	}
}
