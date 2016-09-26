package com.jazinski.BbAuthentication;

public class Main {

	public static void main(String[] args) {
		// BbAuthentication(user_id, shareSecret, BlackboardURL)
		BbAuthentication Bb = new BbAuthentication("test01", "blackboard","https://BbTest.myCollege.edu");
		Bb.setCourse_id("TC-101");
		Bb.setTimestamp("1268769454017"); // Usually not called unless you need to change the timestamp
		System.out.println("As Per Bb Documentation (P8 of the AutoSignon SSO guide) value should be: 8c4956a842e183659ea96478ba7671e2");
		System.out.println("Class: " + Bb.getCourse_id());
		System.out.println("Timestamp: " + Bb.getTimestamp());
		try {
			System.out.println("Auth: " + Bb.calculateHash());
		} catch (Exception ex) {
			System.out.println("Error Calculating HASH: " + ex.toString());
		}
		System.out.println("Full URL: " + Bb.getEncodedURL());
	}

}
