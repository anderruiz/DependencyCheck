package org.owasp.dependencycheck.utils;

import java.nio.charset.Charset;

public interface StandardCharsets {
	Charset UTF_8 = Charset.forName("UTF-8");
	
	Charset US_ASCII = Charset.forName("US-ASCII");
}
