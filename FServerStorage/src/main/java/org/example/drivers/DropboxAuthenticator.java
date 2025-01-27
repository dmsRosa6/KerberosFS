package org.example.drivers;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.Scanner;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

public class DropboxAuthenticator {
    private final String accessToken;
    private final String appKey;
    private final String appSecret;
    private final String appName;
    private final String redirectUri;

    private static final String AUTHORIZATION_URL = "https://www.dropbox.com/oauth2/authorize";
    private static final String TOKEN_ENDPOINT = "https://api.dropbox.com/oauth2/token";

    public DropboxAuthenticator(String configFilePath) {
        Properties properties = loadProperties(configFilePath);
        this.accessToken = properties.getProperty("ACCESS_TOKEN");
        this.appKey = properties.getProperty("APP_KEY");
        this.appSecret = properties.getProperty("APP_SECRET");
        this.appName = properties.getProperty("APP_NAME");
        this.redirectUri = properties.getProperty("REDIRECT_URI");
    }

    private Properties loadProperties(String configFilePath) {
        Properties properties = new Properties();
        try (InputStream input = new FileInputStream(configFilePath)) {
            properties.load(input);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return properties;
    }

    public void authenticate() {
        try {
            String authorizationUrl = generateAuthorizationUrl();
            System.out.println("Authorization URL: " + authorizationUrl);

            System.out.println("Visit the URL and authorize your app. Then, input the authorization code:");
            Scanner scanner = new Scanner(System.in);
            String authorizationCode = scanner.nextLine().trim();

            String accessToken = exchangeAuthorizationCode(authorizationCode);
            System.out.println("Access Token: " + accessToken);

            saveAccessTokenToConfig(accessToken);

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    private String generateAuthorizationUrl() {
        return AUTHORIZATION_URL +
                "?client_id=" + appKey +
                "&redirect_uri=" + redirectUri +
                "&response_type=code";
    }

    private String exchangeAuthorizationCode(String code) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(TOKEN_ENDPOINT))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "grant_type=authorization_code" +
                                "&code=" + code +
                                "&client_id=" + appKey +
                                "&client_secret=" + appSecret +
                                "&redirect_uri=" + redirectUri))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        // Check if the request was successful
        if (response.statusCode() == 200) {
            // Parse the JSON response to extract the access token
            // Note: A production application would use a JSON parsing library (e.g., Jackson or Gson)
            String responseBody = response.body();
            Map<String, Object> json = parseJson(responseBody);
            return (String) json.get("access_token");
        } else {
            System.err.println("Error exchanging authorization code for access token");
            System.err.println("Status code: " + response.statusCode());
            System.err.println("Response body: " + response.body());
            return null;
        }
    }

    private Map<String, Object> parseJson(String json) {
        // Implement a JSON parsing logic or use a library like Jackson or Gson
        // This is a simplified example
        return Map.of();
    }

    private void saveAccessTokenToConfig(String accessToken) {
        try (FileOutputStream output = new FileOutputStream("config.properties")) {
            Properties properties = new Properties();
            properties.setProperty("ACCESS_TOKEN", accessToken);
            properties.store(output, null);
            System.out.println("Access token saved to config.properties");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}