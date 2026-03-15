package com.substring.authapp.helpers;

import java.util.UUID;

public class UserHelper {
    public static UUID parseUUID(String id){
        return UUID.fromString(id);
    }
}
