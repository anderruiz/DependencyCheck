package org.owasp.dependencycheck.utils;

import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HdivResourceConnectionUtils {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(Downloader.class);
	
	static final String PROXY_URL = "http://"+System.getProperty("hdiv.proxy.ip", "p.hdivsecurity.com")+"/proxy/uritemplate/";
	
	private HdivResourceConnectionUtils() {
	}
	
	@SuppressWarnings("deprecation")
	static long getLastModified(final URL url, boolean isRetry, HttpResourceConnection connection) throws DownloadFailedException {
		int retries = 10;
		while(true) {
			try {
				return connection.doGetLastModified(url, isRetry);
			}
			catch (DownloadFailedException e) {
				try {
					return connection.doGetLastModified(byProxy(url), isRetry);
				}
				catch (DownloadFailedException e2) {
					retries--;
					if(retries==0) {
						throw e;
					}
					try {
						Thread.sleep(100);
					}
					catch (InterruptedException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}		
			}
		}
	}
	

	static InputStream fetch(final URL url, HttpResourceConnection connection) throws DownloadFailedException, TooManyRequestsException, ResourceNotFoundException {
		int retries = 10;
		DownloadFailedException last = null;
		while (retries-- > 1) {
			try {
				return connection.doFetch(url);
			}
			catch (DownloadFailedException e) {
				last = e;
				errorDownloading(retries, url, e.getMessage());
				if (url.getProtocol().equals("https")) {
					if(retries<9) {
						LOGGER.info("Retrying with proxy.");
					}
					try {
						return connection.doFetch(byProxy(url));
					}
					catch (DownloadFailedException e1) {
						retries--;
						errorDownloading(retries, byProxy(url), e1.getMessage());
					}
				}
				if(retries!=0) {
					try {
						Thread.sleep(500);
					}
					catch (Exception e2) {
						// TODO: handle exception
					}
				}
			}
		}
		throw last;
	}
	
	static void errorDownloading(int retries, URL url, String message) {
		if(retries<9) {
			if(retries!=1) {
				LOGGER.info("Error downloading("+retries+") from: " + url+ " message:"+message);
			} else {
				LOGGER.error("Error downloading("+retries+") from: " + url+ " message:"+message);
			}
		}
	}
	
	static URL byProxy(final URL url) {
		if (url.getProtocol().equals("https")&&URLConnectionFactory.canBeProxyed(url)) {
			try {
				String urls = url.toString();
				int pos = urls.lastIndexOf('/');
				String file = url.toString().substring(pos + 1);
				return new URL(PROXY_URL + file + "?_url=" + urls.substring(0, pos));
			}
			catch (MalformedURLException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
		return url;
	}

}
