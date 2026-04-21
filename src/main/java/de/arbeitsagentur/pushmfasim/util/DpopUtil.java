package de.arbeitsagentur.pushmfasim.util;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

public class DpopUtil {
    private static final Logger logger = LoggerFactory.getLogger(DpopUtil.class);

    public static final String DEVICE_STATIC_ID = "device-static-id";
    public static final String TOKEN_ENDPOINT = "/protocol/openid-connect/token";

    private DpopUtil() {
        // Utility class, prevent instantiation
    }

    public static String createDpopJwt(String credentialId, String method, String url, RSAKey privateJwk)
            throws Exception {
        return createDpopJwtWithAth(credentialId, method, url, privateJwk, null);
    }

    public static String createDpopJwtWithAth(
            String credentialId, String method, String url, RSAKey privateJwk, String accessToken) throws Exception {
        logger.trace("Creating DPoP JWT - method: {}, url: {}", method, url);

        String userId = extractUserIdFromCredentialId(credentialId);
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .claim("htm", method)
                .claim("htu", url)
                .claim("sub", userId)
                .claim("deviceId", DEVICE_STATIC_ID)
                .issueTime(java.util.Date.from(java.time.Instant.now()))
                .jwtID(UUID.randomUUID().toString());
        if (StringUtils.hasText(accessToken)) {
            claimsBuilder.claim("ath", createAccessTokenHash(accessToken));
        }
        JWTClaimsSet claimsSet = claimsBuilder.build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(privateJwk.toPublicJWK())
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(new RSASSASigner(privateJwk));
        logger.trace(
                "DPoP JWT created successfully with jti: {}",
                signedJWT.getJWTClaimsSet().getJWTID());

        return signedJWT.serialize();
    }

    public static String extractUserIdFromCredentialId(String credentialId) {
        if (credentialId == null || credentialId.isBlank()) {
            return null;
        }

        int aliasIndex = credentialId.indexOf("-device-alias-");
        if (aliasIndex < 0) {
            return null;
        }
        String userId = credentialId.substring(0, aliasIndex);
        return userId.isBlank() ? null : userId;
    }

    public static String getAccessToken(
            RestTemplate restTemplate, String iamUrl, String dPopToken, String clientId, String clientSecret) {
        String url = iamUrl + TOKEN_ENDPOINT;
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("DPoP", dPopToken);
        logger.debug("Requesting access token with client ID: {} from: {}", clientId, url);

        // Use client credentials grant with device client ID/secret
        String body = "grant_type=client_credentials" + "&client_id=" + clientId + "&client_secret=" + clientSecret;

        HttpEntity<String> request = new HttpEntity<>(body, headers);
        try {
            logger.trace("Sending token request to Keycloak");
            ResponseEntity<String> response = restTemplate.postForEntity(url, request, String.class);
            logger.debug("Token endpoint response status: {}", response.getStatusCode());

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                ObjectMapper mapper = new ObjectMapper();
                JsonNode jsonNode = mapper.readTree(response.getBody());
                if (jsonNode.has("access_token")) {
                    String token = jsonNode.get("access_token").asString();
                    logger.debug("Access token obtained successfully, token length: {}", token.length());
                    return token;
                } else {
                    logger.warn("Access token not found in response");
                }
            } else {
                logger.warn(
                        "Token endpoint returned unsuccessful status: {}, body: {}",
                        response.getStatusCode(),
                        response.getBody());
            }
        } catch (Exception e) {
            logger.error("Failed to get access token from {}", url, e);
        }
        return null;
    }

    private static String createAccessTokenHash(String accessToken) throws Exception {
        logger.trace("Creating access token hash for DPoP 'ath' claim");
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(accessToken.getBytes(StandardCharsets.UTF_8));
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }
}
