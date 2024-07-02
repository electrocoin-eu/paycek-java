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
        try {
            String generatedMac = generateMacHash(headers.get("apikeyauth-nonce").get(0), endpoint, bodyString, httpMethod, contentType);

            return MessageDigest.isEqual(generatedMac.getBytes(encoding), headers.get("apikeyauth-mac").get(0).getBytes(encoding));
        } catch (Exception e) {
            return false;
        }
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
     * You can implement getting payment status in 3 ways:
     * <ol>
     *   <li><b>Provide <code>status_url_callback</code></b> upon opening a payment and receive status updates on your endpoint.</li>
     *   <li><b>Provide <code>success_url_callback</code> and <code>fail_url_callback</code></b> upon opening a payment and receive success and fail updates on your endpoints.</li>
     *   <li><b>Manually poll <code>payment/get</code></b> to check payment status.</li>
     * </ol>
     *
     * <p><b>Do not use <code>fail_url</code> and <code>success_url</code> to update payment status in your system. These URLs are used ONLY for redirecting users back to your shop.</b></p>
     *
     *
     * <h4>Authorization</h4>
     * <p>If you decide to use callbacks, you <b>must check the headers for every callback</b> to ensure they are authorized.
     * If a callback doesn't have a valid Authorization header, your server must respond with a <b>401 Unauthorized</b> status. If the callback has a valid Authorization header, your server must respond with a <b>200 OK</b> status.</p>
     *
     * <h4>Integration Testing</h4>
     * <p>In order to ensure system security, on every new payment, an automated integration test will check if your integration is secure.
     * An API call with an invalid Authorization header will be made to each of your callback endpoints. If any endpoint returns a status other than 401 for requests with an invalid Authorization header, <b>all ongoing payments will be canceled</b>, and your <b>profile will be blocked</b> to prevent unauthorized transactions. Ensure your endpoints are correctly configured to handle authorization and respond appropriately.</p>
     *
     *
     * <p><i>Test profiles won't be blocked even if the response for callbacks with an invalid Authorization header returns an invalid status. The payment will still be canceled.</i></p>
     *
     * @param profileCode The profile code for the payment.
     * @param dstAmount The amount of the payment.
     * @param optionalFields Optional fields:
     * <ul>
     *   <li>payment_id: string</li>
     *   <li>location_id: string</li>
     *   <li>items: array</li>
     *   <li>email: string</li>
     *   <li>success_url: string</li>
     *   <li>fail_url: string</li>
     *   <li>back_url: string</li>
     *   <li>success_url_callback: string</li>
     *   <li>fail_url_callback: string</li>
     *   <li>status_url_callback: string</li>
     *   <li>description: string</li>
     *   <li>language: string</li>
     *   <li>generate_pdf: boolean</li>
     *   <li>client_fields: Object</li>
     * </ul>
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