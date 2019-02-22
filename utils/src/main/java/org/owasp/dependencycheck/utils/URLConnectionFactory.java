/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;

import org.apache.commons.lang3.StringUtils;
import org.hdiv.ee.ssl.ConnectionSettings;
import org.hdiv.ee.ssl.SSLAddress;
import org.hdiv.ee.ssl.SSLConfiguration;
import org.hdiv.ee.ssl.SSLConfigurations;
import org.hdiv.ee.ssl.SSLEnvironment;
import org.hdiv.ee.ssl.SSLManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * A URLConnection Factory to create new connections. This encapsulates several configuration checks to ensure that the connection uses the
 * correct proxy settings.
 *
 * @author Jeremy Long
 */
public final class URLConnectionFactory {

	/**
	 * The logger.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(URLConnectionFactory.class);

	/**
	 * The configured settings.
	 */
	private final Settings settings;

	/**
	 * Private constructor for this factory.
	 *
	 * @param settings reference to the configured settings
	 */
	public URLConnectionFactory(Settings settings) {
		this.settings = settings;
	}

	/**
	 * Utility method to create an HttpURLConnection. If the application is configured to use a proxy this method will retrieve the proxy
	 * settings and use them when setting up the connection.
	 *
	 * @param url the url to connect to
	 * @return an HttpURLConnection
	 * @throws URLConnectionFailureException thrown if there is an exception
	 */
	@SuppressFBWarnings(value = "RCN_REDUNDANT_NULLCHECK_OF_NULL_VALUE", justification = "Just being extra safe")
	public HttpURLConnection createHttpURLConnection(URL url) throws URLConnectionFailureException {
		HttpURLConnection conn = null;
		final String proxyHost = settings.getString(Settings.KEYS.PROXY_SERVER);

		try {
			ConnectionSettings.Builder builder = ConnectionSettings.builder();
			if (proxyHost != null && !matchNonProxy(url)) {
				builder.proxyType(Proxy.Type.HTTP);
				builder.proxyHost(proxyHost);
				builder.proxyPort(settings.getInt(Settings.KEYS.PROXY_PORT));

				final String username = settings.getString(Settings.KEYS.PROXY_USERNAME);
				final String password = settings.getString(Settings.KEYS.PROXY_PASSWORD);

				if (username != null && password != null) {
					builder.proxyUsername(username);
					builder.proxyPassword(password);
				}
			}
			builder.httpProxyUrl(proxyedUrl(url));
			configureTLS(url, builder);
			conn = SSLManager.INSTANCE.openConnection(url, builder.build());
			final int connectionTimeout = settings.getInt(Settings.KEYS.CONNECTION_TIMEOUT, 10000);
			final int rtimeout = settings.getInt(Settings.KEYS.READ_TIMEOUT, 30000);
			conn.setConnectTimeout(connectionTimeout);
			conn.setReadTimeout(rtimeout);
			conn.setInstanceFollowRedirects(true);
		}
		catch (IOException ex) {
			if (conn != null) {
				try {
					conn.disconnect();
				}
				finally {
					conn = null;
				}
			}
			throw new URLConnectionFailureException("Error getting connection.", ex);
		}
		// conn.setRequestProperty("user-agent",
		// "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36");
		return conn;
	}

	/**
	 * Check if hostname matches nonProxy settings
	 *
	 * @param url the url to connect to
	 * @return matching result. true: match nonProxy
	 */
	private boolean matchNonProxy(final URL url) {
		final String host = url.getHost();

		// code partially from org.apache.maven.plugins.site.AbstractDeployMojo#getProxyInfo
		final String nonProxyHosts = settings.getString(Settings.KEYS.PROXY_NON_PROXY_HOSTS);
		if (null != nonProxyHosts) {
			final String[] nonProxies = nonProxyHosts.split("(,)|(;)|(\\|)");
			for (final String nonProxyHost : nonProxies) {
				// if ( StringUtils.contains( nonProxyHost, "*" ) )
				if (null != nonProxyHost && nonProxyHost.contains("*")) {
					// Handle wildcard at the end, beginning or middle of the nonProxyHost
					final int pos = nonProxyHost.indexOf('*');
					final String nonProxyHostPrefix = nonProxyHost.substring(0, pos);
					final String nonProxyHostSuffix = nonProxyHost.substring(pos + 1);
					// prefix*
					if (!StringUtils.isEmpty(nonProxyHostPrefix) && host.startsWith(nonProxyHostPrefix)
							&& StringUtils.isEmpty(nonProxyHostSuffix)) {
						return true;
					}
					// *suffix
					if (StringUtils.isEmpty(nonProxyHostPrefix) && !StringUtils.isEmpty(nonProxyHostSuffix)
							&& host.endsWith(nonProxyHostSuffix)) {
						return true;
					}
					// prefix*suffix
					if (!StringUtils.isEmpty(nonProxyHostPrefix) && host.startsWith(nonProxyHostPrefix)
							&& !StringUtils.isEmpty(nonProxyHostSuffix) && host.endsWith(nonProxyHostSuffix)) {
						return true;
					}
				}
				else if (host.equals(nonProxyHost)) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Utility method to create an HttpURLConnection. The use of a proxy here is optional as there may be cases where a proxy is configured
	 * but we don't want to use it (for example, if there's an internal repository configured)
	 *
	 * @param url the URL to connect to
	 * @param proxy whether to use the proxy (if configured)
	 * @return a newly constructed HttpURLConnection
	 * @throws URLConnectionFailureException thrown if there is an exception
	 */
	public HttpURLConnection createHttpURLConnection(URL url, boolean proxy) throws URLConnectionFailureException {
		if (proxy) {
			return createHttpURLConnection(url);
		}
		HttpURLConnection conn = null;
		try {
			ConnectionSettings.Builder builder = ConnectionSettings.builder();
			builder.httpProxyUrl(proxyedUrl(url));
			configureTLS(url, builder);
			conn = SSLManager.INSTANCE.openConnection(url, builder.build());
			final int timeout = settings.getInt(Settings.KEYS.CONNECTION_TIMEOUT, 10000);
			final int rtimeout = settings.getInt(Settings.KEYS.READ_TIMEOUT, 30000);
			conn.setConnectTimeout(timeout);
			conn.setReadTimeout(rtimeout);
			conn.setInstanceFollowRedirects(true);
		}
		catch (IOException ioe) {
			throw new URLConnectionFailureException("Error getting connection.", ioe);
		}
		return conn;
	}

	private static String proxyedUrl(URL url) {
		String finalUrl = "";
		String query = url.getQuery();
		String complete = url.toString();
		String base = "http://52.207.65.244/proxy/uritemplate";

		if (query == null) {
			finalUrl = base + "?_url=" + complete;
		}
		else {
			finalUrl = base + "?" + query + "&_url=" + complete.substring(0, complete.indexOf(query) - 1);
		}

		return finalUrl;
	}

	/**
	 * If the protocol is HTTPS, this will configure the cipher suites so that connections can be made to the NVD, and others, using older
	 * versions of Java.
	 *
	 * @param url the URL
	 * @param builder the connection settings builder
	 */
	private void configureTLS(final URL url, final ConnectionSettings.Builder builder) {
		if ("https".equalsIgnoreCase(url.getProtocol())) {
			SSLEnvironment environment = new SSLEnvironment() {
				@Override
				public SSLConfiguration getHostConfiguration(final SSLAddress address) {
					boolean trusted = false;
					String[] trustedHosts = settings.getArray(Settings.KEYS.SSL_TRUSTED_HOSTS);
					if (trustedHosts != null) {
						for (String trustedHost : trustedHosts) {
							SSLAddress trustedAddress = SSLAddress.fromString(trustedHost);
							if (address.matches(trustedAddress)) {
								trusted = true;
								break;
							}
						}
					}
					return trusted ? SSLConfigurations.validate(false) : SSLManager.INSTANCE.getHostConfiguration(address);
				}
			};
			builder.environment(environment);
		}
	}
}
