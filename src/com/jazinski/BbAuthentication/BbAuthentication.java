package com.jazinski.BbAuthentication;

import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * This is going to be the Class used to generate a Blackboard URL for use with the AutoSignon SSO Building Block
 * @author Christopher Jazinski
 * @required user_id
 * @required timestamp - Will default to init timestamp
 * @required BbHost
 * @required sharedSecret
 */
public class BbAuthentication {
	/**
	 * Needed private parameters
	 */
	private String user_id;
	private String timestamp;
	private String course_id;
	private String forward_url;
	private String sharedSecret;
	private String BbHost;
	
	public BbAuthentication(String username, String shareSecret, String bbHost) {
		this.setUser_id(username);
		this.setSharedSecret(shareSecret);
		this.setBbHost(bbHost);
		this.setTimestamp(null);
	}


	public String getSharedSecret() {
		return sharedSecret;
	}

	public void setSharedSecret(String sharedSecret) {
		this.sharedSecret = sharedSecret;
	}

	public String getUser_id() {
		return user_id;
	}

	public void setUser_id(String user_id) {
		this.user_id = user_id;
	}

	public String getCourse_id() {
		return course_id;
	}

	public void setCourse_id(String course_id) {
		this.course_id = course_id;
	}

	public String getForward_url() {
		return forward_url;
	}

	public void setForward_url(String forward_url) {
		this.forward_url = forward_url;
	}

	public String getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(String ts) {
		//TODO - Should probably validate that a correct time is being passed in. 
		if (ts == null) {
			long temp = System.currentTimeMillis() / 1000;
			this.timestamp = Long.toString(temp);
		} else {
			this.timestamp = ts;
		}
	}
	
	public String getBbHost() {
		return BbHost;
	}

	public void setBbHost(String bbHost) {
		BbHost = bbHost;
	}
	
	public String getBbAPIURL() {
		String API = "/webapps/bbgs-autosignon-BBLEARN/autoSignon.do";
		return this.getBbHost() + API;
	}

	public String getEncodedURL() {
		String URL = this.getBbAPIURL();
		List<String> params  = this.createParamList();
		String parameter = "";
		for (String param : params) {
			parameter += param;
		}
		try {
			URL += parameter + "&auth=" + this.calculateHash();
		} catch (Exception ex) {
			System.out.println("Could not calculater HASH: " +  parameter);
		}
		return URL;
	}
	
	// Private Stuff
	private List<String> createParamList() {
		List<String> params = new ArrayList<String>();
		String delimiter = "?";		
		/**
		 * @param course_id
		 * @param forward_url
		 * @required timestamp
		 * @required user_id		 
		 * @required auth (will be filled in later)
		 */
		if (this.getCourse_id() != null) {
			params.add(delimiter + "courseId=" + this.getCourse_id());
			delimiter = "&";
		}
		
		if (this.getForward_url() != null) {
			try {
				params.add(delimiter + "forward=" + URLEncoder.encode(this.getForward_url(), "UTF-8"));
			} catch (Exception ex) {
				System.out.println("Could not encode URL: " + this.getForward_url());
			}
			delimiter = "&";
		}
		
		if (this.getTimestamp() != null) {
			params.add(delimiter + "timestamp=" + this.getTimestamp());
			delimiter = "&";
		} else {
			//This is an error as its @required we can recover though
			this.setTimestamp(null);
			params.add(delimiter + "timestamp=" + this.getTimestamp());
			delimiter = "&";
		}
		
		if (this.getUser_id() != null) {
			params.add(delimiter + "userId=" + this.getUser_id());
		} else {
			//This is an error as its @required
			System.out.println("User_ID: NULL");
		}
		
		return params;
	}
	
	private String createParamToHash() {
		String params = "";
		/**
		 * @param course_id
		 * @param forward_url
		 * @required timestamp
		 * @required user_id		 
		 * @required auth (will be filled in later)
		 */
		if (this.getCourse_id() != null) {
			params += this.getCourse_id();
		}
		
		if (this.getForward_url() != null) {
			try {
				params += URLEncoder.encode(this.getForward_url(), "UTF-8");
			} catch (Exception ex) {
				System.out.println("Could not encode URL: " + this.getForward_url());
			}
		}
		
		if (this.getTimestamp() != null) {
			params += this.getTimestamp();
		} else {
			//This is an error as its @required we can recover though
			this.setTimestamp(null);
			params += this.getTimestamp();
		}
		
		if (this.getUser_id() != null) {
			params += this.getUser_id();
		} else {
			//This is an error as its @required
			System.out.println("User_ID: NULL");
		}
		
		return params;
	}
	
	//Should be private - but marking it as public to view in the Main class
	public String calculateHash() 
		throws NoSuchAlgorithmException {
		
		String paramString = this.createParamToHash();		
		
		// get md5 has from ascii value and secret
		final MessageDigest md = MessageDigest.getInstance("MD5");
		final byte[] hashBytes = md.digest((paramString + this.getSharedSecret()).getBytes());
		md.reset();
		
		// Convert to hex
		String mac = "";
		String hexByte;
		
		for (int i=0; i <hashBytes.length; i++) {
			hexByte = Integer.toHexString(hashBytes[i] < 0 ? hashBytes[i] + 256 : hashBytes[i]);
			mac += (hexByte.length() == 1) ? "0" + hexByte : hexByte;
		}
		return mac;
	}
	
}