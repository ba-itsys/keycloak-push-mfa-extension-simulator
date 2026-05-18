package de.arbeitsagentur.pushmfasim.util;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

public class UrlUtil {
    private static final Logger logger = LoggerFactory.getLogger(UrlUtil.class);

    private UrlUtil() {
        // Utility class, prevent instantiation
    }

    /**
     * If the given IAM URL contains "localhost", this method checks which of the possible localhost base URLs is reachable and returns the reachable one.
     * This is useful in Docker environments where "localhost" might not be accessible from within the container, but "host.docker.internal" or "keycloak" might be.
     * If the given IAM URL does not contain "localhost", it is returned unchanged.
     */
    public static String tryLocalhostBaseUrls(String iamUrl, RestTemplate restTemplate) {
        if (iamUrl.contains("localhost")) {
            // Check which URL is reachable
            HttpHeaders headers = new HttpHeaders();
            headers.add("userId", "not-relevant-for-check");
            HttpEntity<String> entity = new HttpEntity<>(headers);
            iamUrl = getUrl(iamUrl, "/login/pending/", restTemplate, entity);
        }
        return iamUrl;
    }

    private static String getUrl(String iamUrl, String endpoint, RestTemplate restTemplate, HttpEntity<String> entity) {
        List<String> possibleUrls = List.of(
                iamUrl, iamUrl.replace("localhost", "host.docker.internal"), iamUrl.replace("localhost", "keycloak"));
        for (String url : possibleUrls) {
            String endpointUrl = url + endpoint;
            try {
                restTemplate.exchange(endpointUrl, HttpMethod.GET, entity, String.class);
            } catch (ResourceAccessException e) {
                logger.debug("ResourceAccessException at {}: {}", endpointUrl, e.getMessage());
            } catch (HttpClientErrorException e) {
                // at least this host is reachable, even if the endpoint is not found (which is expected in this check)
                logger.debug("HttpClientErrorException at {}: {}", endpointUrl, e.getStatusCode());
                iamUrl = url;
                break;
            }
        }
        return iamUrl;
    }
}
