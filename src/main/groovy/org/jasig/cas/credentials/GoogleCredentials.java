package org.jasig.cas.credentials;

import org.jasig.cas.authentication.principal.Credentials;

/**
 * Created by swlyons on 8/1/2016.
 */
public class GoogleCredentials implements Credentials {
    private final String userID;
    private final String accessToken;

    public GoogleCredentials(final String accessToken, final String userID) {
        this.userID = userID;
        this.accessToken = accessToken;
    }

    public final String getUserID() {
        return userID;
    }

    public final String getAccessToken() {
        return accessToken;
    }

    @Override
    public String toString() {
        return "";
    }
}
