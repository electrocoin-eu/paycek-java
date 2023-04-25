package io.paycek;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.sun.net.httpserver.Headers;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class Paycek {
    private final String apiKey;
    private final String apiSecret;
    private final String apiHost;
    private final String apiPrefix;
    private final Charset encoding;

    public Paycek(String apiKey, String apiSecret) {
        this.apiKey = apiKey;
        this.apiSecret = apiSecret;
        this.apiHost = "https://paycek.io";
        this.apiPrefix = "/processing/api";
        this.encoding = StandardCharsets.UTF_8;
    }

    private void updateDigest(SHA3.Digest512 digest, String value) {
        digest.update((byte) 0);
        digest.update(value.getBytes(encoding));
    }

    private String generateMacHash(String nonceStr, String endpoint, String bodyString, String httpMethod, String contentType) {
        SHA3.Digest512 digest = new SHA3.Digest512();

        this.updateDigest(digest, apiKey);
        this.updateDigest(digest, apiSecret);
        this.updateDigest(digest, nonceStr);
        this.updateDigest(digest, httpMethod);
        this.updateDigest(digest, endpoint);
        this.updateDigest(digest, contentType);
        this.updateDigest(digest, bodyString);
        digest.update((byte) 0);

        return Hex.toHexString(digest.digest());
    }

    private String generateMacHash(String nonceStr, String endpoint, String bodyString) {
        return generateMacHash(nonceStr, endpoint, bodyString, "POST", "application/json");
    }

    private Map<String, Object> apiCall(String endpoint, Map<String, Object> body) {
        String prefixedEndpoint = String.format("%s/%s", apiPrefix, endpoint);
        Gson gson = new Gson();
        String bodyString = gson.toJson(body);
        String nonceStr = Long.toString(System.currentTimeMillis());

        String macHash = generateMacHash(nonceStr, prefixedEndpoint, bodyString);

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(apiHost + prefixedEndpoint))
                .header("Content-Type", "application/json")
                .header("ApiKeyAuth-Key", apiKey)
                .header("ApiKeyAuth-Nonce", nonceStr)
                .header("ApiKeyAuth-MAC", macHash)
                .POST(HttpRequest.BodyPublishers.ofString(bodyString))
                .build();

        HttpResponse<String> response;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }

        return gson.fromJson(response.body(), new TypeToken<Map<String, Object>>() {}.getType());
    }

    /**
     * This method is used to verify callback was encoded by paycek.
     * A mac digest will be created by encoding nonce from headers, endpoint, body bytes, your api key and secret, http method and content type.
     * That value will be compared with mac digest from headers.
     *
     * @param headers     callback headers
     * @param endpoint    callback endpoint
     * @param bodyString  callback body string
     * @param httpMethod  callback http method
     * @param contentType callback content type
     * @return true if the generated mac digest is equal to the one received in headers, false otherwise
     */
    public boolean checkHeaders(Headers headers, String endpoint, String bodyString, String httpMethod, String contentType) {
        String generatedMac = generateMacHash(headers.get("apikeyauth-nonce").get(0), endpoint, bodyString, httpMethod, contentType);

        return MessageDigest.isEqual(generatedMac.getBytes(encoding), headers.get("apikeyauth-mac").get(0).getBytes(encoding));
    }

    public boolean checkHeaders(Headers headers, String endpoint, String bodyString) {
        return checkHeaders(headers, endpoint, bodyString, "GET", "");
    }

    /**
     * @param optionalFields optional fields:
     *                       payment_id: String
     *                       location_id: String
     *                       items: List
     *                       email: String
     *                       success_url: String
     *                       fail_url: String
     *                       back_url: String
     *                       success_url_callback: String
     *                       fail_url_callback: String
     *                       status_url_callback: String
     *                       description: String
     *                       language: String
     *                       generate_pdf: Boolean
     *                       client_fields: Map
     */
    public String generatePaymentUrl(String profileCode, String dstAmount, Map<String, Object> optionalFields) {
        Map<String, Object> payment = openPayment(profileCode, dstAmount, optionalFields);

        try {
            return ((Map<String, Object>) payment.get("data")).get("payment_url").toString();
        } catch (Exception ex) {
            System.out.println(payment);
            throw ex;
        }
    }

    public String generatePaymentUrl(String profileCode, String dstAmount) {
        return generatePaymentUrl(profileCode, dstAmount, Collections.emptyMap());
    }

    public Map<String, Object> getPayment(String paymentCode) {
        Map<String, Object> body = new HashMap<>();
        body.put("payment_code", paymentCode);

        return apiCall("payment/get", body);
    }

    /**
     * @param optionalFields optional fields:
     *                       payment_id: String
     *                       location_id: String
     *                       items: List
     *                       email: String
     *                       success_url: String
     *                       fail_url: String
     *                       back_url: String
     *                       success_url_callback: String
     *                       fail_url_callback: String
     *                       status_url_callback: String
     *                       description: String
     *                       language: String
     *                       generate_pdf: Boolean
     *                       client_fields: Map
     */
    public Map<String, Object> openPayment(String profileCode, String dstAmount, Map<String, Object> optionalFields) {
        Map<String, Object> body = new HashMap<>();
        body.put("profile_code", profileCode);
        body.put("dst_amount", dstAmount);
        body.putAll(optionalFields);

        return apiCall("payment/open", body);
    }

    public Map<String, Object> openPayment(String profileCode, String dstAmount) {
        return openPayment(profileCode, dstAmount, Collections.emptyMap());
    }

    /**
     * @param optionalFields optional fields:
     *                       src_protocol: String
     */
    public Map<String, Object> updatePayment(String paymentCode, String srcCurrency, Map<String, Object> optionalFields) {
        Map<String, Object> body = new HashMap<>();
        body.put("payment_code", paymentCode);
        body.put("src_currency", srcCurrency);
        body.putAll(optionalFields);

        return apiCall("payment/update", body);
    }

    public Map<String, Object> updatePayment(String paymentCode, String srcCurrency) {
        return updatePayment(paymentCode, srcCurrency, Collections.emptyMap());
    }

    public Map<String, Object> cancelPayment(String paymentCode) {
        Map<String, Object> body = new HashMap<>();
        body.put("payment_code", paymentCode);

        return apiCall("payment/cancel", body);
    }

    public Map<String, Object> getProfileInfo(String profileCode) {
        Map<String, Object> body = new HashMap<>();
        body.put("profile_code", profileCode);

        return apiCall("profile_info/get", body);
    }

    /**
     * @param optionalFields optional fields:
     *                       location_id: String
     *                       items: List
     *                       email: String
     *                       success_url: String
     *                       fail_url: String
     *                       back_url: String
     *                       success_url_callback: String
     *                       fail_url_callback: String
     *                       status_url_callback: String
     *                       description: String
     *                       language: String
     *                       generate_pdf: Boolean
     *                       client_fields: Map
     */
    public Map<String, Object> profileWithdraw(String profileCode, String method, String amount, Map<String, Object> details, Map<String, Object> optionalFields) {
        Map<String, Object> body = new HashMap<>();
        body.put("profile_code", profileCode);
        body.put("method", method);
        body.put("amount", amount);
        body.put("details", details);
        body.putAll(optionalFields);

        return apiCall("profile/withdraw", body);
    }

    public Map<String, Object> profileWithdraw(String profileCode, String method, String amount, Map<String, Object> details) {
        return profileWithdraw(profileCode, method, amount, details, Collections.emptyMap());
    }

    /**
     * @param profileAutomaticWithdrawDetails automatic withdraw details map with fields:
     *                                        iban: String (required)
     *                                        purpose: String
     *                                        model: String
     *                                        pnb: String
     * @param optionalFields                  optional fields:
     *                                        type: String
     *                                        oib: String
     *                                        vat: String
     *                                        profile_name: String
     *                                        profile_email: String
     *                                        profile_type: String
     */
    public Map<String, Object> createAccount(String email, String name, String street, String city, String country, String profileCurrency, String profileAutomaticWithdrawMethod, Map<String, Object> profileAutomaticWithdrawDetails, Map<String, Object> optionalFields) {
        Map<String, Object> body = new HashMap<>();
        body.put("email", email);
        body.put("name", name);
        body.put("street", street);
        body.put("city", city);
        body.put("country", country);
        body.put("profile_currency", profileCurrency);
        body.put("profile_automatic_withdraw_method", profileAutomaticWithdrawMethod);
        body.put("profile_automatic_withdraw_details", profileAutomaticWithdrawDetails);
        body.putAll(optionalFields);

        return apiCall("account/create", body);
    }

    public Map<String, Object> createAccount(String email, String name, String street, String city, String country, String profileCurrency, String profileAutomaticWithdrawMethod, Map<String, Object> profileAutomaticWithdrawDetails) {
        return createAccount(email, name, street, city, country, profileCurrency, profileAutomaticWithdrawMethod, profileAutomaticWithdrawDetails, Collections.emptyMap());
    }

    /**
     * @param profileAutomaticWithdrawDetails automatic withdraw details map with fields:
     *                                        iban: String (required)
     *                                        purpose: String
     *                                        model: String
     *                                        pnb: String
     * @param optionalFields                  optional fields:
     *                                        type: String
     *                                        oib: String
     *                                        vat: String
     *                                        profile_name: String
     *                                        profile_email: String
     */
    public Map<String, Object> createAccountWithPassword(String email, String password, String name, String street, String city, String country, String profileCurrency, String profileAutomaticWithdrawMethod, Map<String, Object> profileAutomaticWithdrawDetails, Map<String, Object> optionalFields) {
        Map<String, Object> body = new HashMap<>();
        body.put("email", email);
        body.put("password", password);
        body.put("name", name);
        body.put("street", street);
        body.put("city", city);
        body.put("country", country);
        body.put("profile_currency", profileCurrency);
        body.put("profile_automatic_withdraw_method", profileAutomaticWithdrawMethod);
        body.put("profile_automatic_withdraw_details", profileAutomaticWithdrawDetails);
        body.putAll(optionalFields);

        return apiCall("account/create_with_password", body);
    }

    public Map<String, Object> createAccountWithPassword(String email, String password, String name, String street, String city, String country, String profileCurrency, String profileAutomaticWithdrawMethod, Map<String, Object> profileAutomaticWithdrawDetails) {
        return createAccountWithPassword(email, password, name, street, city, country, profileCurrency, profileAutomaticWithdrawMethod, profileAutomaticWithdrawDetails, Collections.emptyMap());
    }

    /**
     * @param optionalFields optional fields:
     *                       location_id: String
     */
    public Map<String, Object> getReports(String profileCode, String datetimeFrom, String datetimeTo, Map<String, Object> optionalFields) {
        Map<String, Object> body = new HashMap<>();
        body.put("profile_code", profileCode);
        body.put("datetime_from", datetimeFrom);
        body.put("datetime_to", datetimeTo);
        body.putAll(optionalFields);

        return apiCall("reports/get", body);
    }

    public Map<String, Object> getReports(String profileCode, String datetimeFrom, String datetimeTo) {
        return getReports(profileCode, datetimeFrom, datetimeTo, Collections.emptyMap());
    }
}