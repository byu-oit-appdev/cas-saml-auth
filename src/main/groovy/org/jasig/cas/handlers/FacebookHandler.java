package org.jasig.cas.handlers;

/**
 * Created by swlyons on 7/29/2016.
 */

import org.jasig.cas.credentials.FacebookCredentials;
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

public class FacebookHandler implements NamedAuthenticationHandler, InitializingBean {


    @NotNull
    private String facebookApiId;

    @NotNull
    private String facebookApiSecret;

    public void setFacebookApiId(String facebookApiId) {
        this.facebookApiId = facebookApiId;
    }

    public void setFacebookApiSecret(String facebookApiSecret) {
        this.facebookApiSecret = facebookApiSecret;
    }

    @Override
    public String getName() {
        return "FacebookHandler";
    }

    @Override
    public boolean authenticate(Credentials credentials) throws AuthenticationException {
        FacebookCredentials facebookCredentials = (FacebookCredentials) credentials;
        String accessToken = facebookCredentials.getAccessToken();
        String userID = facebookCredentials.getUserID();
        HttpURLConnection connection = null;
        try {
            URL url = new URL("https://graph.facebook.com/debug_token?input_token=" + accessToken + "&access_token=" + facebookApiId + "|" + facebookApiSecret);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setUseCaches(false);

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

            JSONObject json = (new JSONObject(response.toString()).getJSONObject("data"));

            if (json.getBoolean("is_valid") && json.getString("app_id").equals(facebookApiId) && json.getString("user_id").equals(userID)) {
                return true;
            }else {
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
        return credentials == null ? false : (credentials instanceof FacebookCredentials);
    }

    @Override
    public void afterPropertiesSet() throws Exception {

    }
}
