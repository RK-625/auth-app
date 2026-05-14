package com.substring.authapp.utils;

public class PrivacyHelper {

    private PrivacyHelper() {
        // Utility class
    }

    public static String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return email;
        }
        String[] parts = email.split("@");
        String localPart = parts[0];
        String domainPart = parts[1];

        if (localPart.length() <= 2) {
            return localPart.charAt(0) + "***" + (localPart.length() == 2 ? localPart.charAt(1) : "") + "@" + domainPart;
        }

        return localPart.charAt(0) + "***" + localPart.charAt(localPart.length() - 1) + "@" + domainPart;
    }
}
