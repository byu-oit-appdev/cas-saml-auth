package org.jasig.cas.handlers;

/**
 * Created by swlyons on 7/29/2016.
 */

import org.jasig.cas.credentials.GoogleCredentials;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.handler.NamedAuthenticationHandler;
import org.jasig.cas.authentication.principal.Credentials;
import org.json.JSONObject;

import javax.validation.constraints.NotNull;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import org.springframework.beans.factory.InitializingBean;

public class GoogleHandler implements NamedAuthenticationHandler, InitializingBean {


    @NotNull
    private String googleApiId;

    public void setGoogleApiId(String googleApiId) {
        this.googleApiId = googleApiId;
    }

    @Override
    public String getName() {
        return "GoogleHandler";
    }

    @Override
    public boolean authenticate(Credentials credentials) throws AuthenticationException {
        GoogleCredentials googleCredentials = (GoogleCredentials) credentials;
        String userAccessToken = googleCredentials.getAccessToken();
        String userID = googleCredentials.getUserID();
        HttpURLConnection connection = null;
        try {
            URL url = new URL("https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=" + userAccessToken);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setUseCaches(false);

            if(connection.getResponseCode()!=200){
                return false;
            }

            InputStream is = connection.getInputStream();
            BufferedReader rd = new BufferedReader(new InputStreamReader(is));
            StringBuilder response = new StringBuilder();
            String line;

            while ((line = rd.readLine()) != null) {
                response.append(line);
            }

            rd.close();
            if (connection != null) {
                connection.disconnect();
            }

            JSONObject json = new JSONObject(response.toString());

            if ((json.getString("iss").equals("accounts.google.com")||json.getString("iss").equals("https://accounts.google.com"))&&0<json.getInt("exp")&&json.getString("aud").equals(googleApiId)&&json.getString("sub").equals(userID)) {
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            if (connection != null) {
                connection.disconnect();
            }
            return false;
        }
    }

    @Override
    public boolean supports(Credentials credentials) {
        return credentials == null ? false : (credentials instanceof GoogleCredentials);
    }

    @Override
    public void afterPropertiesSet() throws Exception {

    }
}
