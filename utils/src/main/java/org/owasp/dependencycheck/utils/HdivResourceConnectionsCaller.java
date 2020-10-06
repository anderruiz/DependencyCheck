package org.owasp.dependencycheck.utils;

import static java.lang.String.format;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.zip.GZIPInputStream;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

public class HdivResourceConnectionsCaller {
	
	static final boolean MOCK_ENABLED = Boolean.getBoolean("hdiv.dependency.file.mock");
	
	static final String PROXY_URL = "http://"+System.getProperty("hdiv.proxy.ip", "p.hdivsecurity.com")+"/proxy/uritemplate/";
	
	public static InputStream verify(InputStream in, URL url, boolean proxy) throws DownloadFailedException {
		try {
			InputStream io = in;
			if(MOCK_ENABLED) {
				String fileName = url.toString().substring(url.toString().lastIndexOf('/')+1);
		    	File file = new File(fileName+(proxy?".proxy":""));
		    	if(file.exists()) {
		    		in.close();
		    		io = new FileInputStream(file);
		    	}
			}
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			IOUtils.copy(io, out);
			if(verify(url, out.toByteArray())) {
				return new ByteArrayInputStream(out.toByteArray());
			}
			final String msg = format("Download failed, unable to copy '%s'", url.toString());
	        throw new DownloadFailedException(msg);
		}
		catch (DownloadFailedException e) {
			throw e;
		} catch (IOException e) {
			final String msg = format("Download failed, unable to copy '%s'", url.toString());
	        throw new DownloadFailedException(msg, e);
		}

	}
	
	private static boolean verify(URL url, byte [] data) {
		String fileType = url.toString().substring(url.toString().lastIndexOf('.')+1);
		if("json".equals(fileType)) {
				String value = read(data);
				return (value.startsWith("{")&&value.endsWith("}") ||
						value.startsWith("[")&&value.endsWith("]"));
		} else if("gz".equals(fileType)) {
			return isGZipped(data);
		} else if("xml".equals(fileType)||"pom".equals(fileType)) {
			String value = read(data);
			return value.contains("<")&&value.contains("</")&&value.contains(">");
		} else if("meta".equals(fileType)) {
			return read(data).contains("lastModifiedDate");
		} else {
			System.out.println("Unknown file type:"+fileType+" from URL:"+url);
		}
		return true;
	}
	
	static String read(byte[] bdata) {
		try {
			char [] data = new String(bdata, "UTF-8").toCharArray();
			int start = 0, end = data.length;
			for (int i = 0; i < data.length; i++) {
				if(Character.isWhitespace(data[i])) {
					start++;
				} else {
					break;
				}
			}
			for (int i = data.length-1; i >= start; i--) {
				if(Character.isWhitespace(data[i])) {
					end = i;
				} else {
					break;
				}
			}
			return new String(data, start, end-start);
		}
		catch (Exception e) {
			return "";
		}
	}
	
	static InputStream download(HttpResourceConnection connection, URL url, boolean proxy) throws TooManyRequestsException, ResourceNotFoundException, DownloadFailedException {
		if(proxy) {
			return verify(connection.doFetch(byProxy(url)), url, proxy);
		} else {
			return verify(connection.doFetch(url), url, proxy);
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
	
	public static boolean isGZipped(byte [] data) {
		int magic = 0;
		try {
			magic = data[0] & 0xff | ((data[1] << 8) & 0xff00);
		} catch (Throwable e) {
		   e.printStackTrace(System.err);
		}
		return magic == GZIPInputStream.GZIP_MAGIC;
	}
	
	public static void main(String [] args) throws MalformedURLException {
		System.out.println(verify(new URL("https://search.maven.org/remotecontent?filepath=aopalliance/aopalliance/1.0/aopalliance-1.0.pom"), ("\n"
				+ "<project>\n"
				+ "  <modelVersion>4.0.0</modelVersion>\n"
				+ "  <groupId>aopalliance</groupId>\n"
				+ "  <artifactId>aopalliance</artifactId>\n"
				+ "  <name>AOP alliance</name>\n"
				+ "  <version>1.0</version>\n"
				+ "  <description>AOP Alliance</description>\n"
				+ "  <url>http://aopalliance.sourceforge.net</url> \n"
				+ "\n"
				+ "  <licenses>\n"
				+ "    <license>\n"
				+ "      <name>Public Domain</name>\n"
				+ "    </license>\n"
				+ "  </licenses>\n"
				+ "</project>").getBytes()));
		System.out.println(verify(new URL("https://search.maven.org/remotecontent?filepath=aopalliance/aopalliance/1.0/aopalliance-1.0.json"), "{}\n".getBytes()));
	}

}
