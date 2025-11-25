package cue.edu.co.apigateway.security.util;

import cue.edu.co.apigateway.models.RouteRule;
import org.springframework.http.server.reactive.ServerHttpRequest;

public class RouteMatcher {

    public static boolean matches(ServerHttpRequest request, RouteRule rule) {
        if (!request.getMethod().equals(rule.method())) return false;

        String path = request.getURI().getPath();

        if (rule.regex()) {
            return path.matches(rule.pattern());
        }

        return path.startsWith(rule.pattern());
    }
}