package cue.edu.co.apigateway.constants;

import cue.edu.co.apigateway.models.RouteRule;
import org.springframework.http.HttpMethod;

import java.util.List;


public class RouteConstant {

    public static final List<RouteRule> PUBLIC_ROUTES = List.of(
            new RouteRule(HttpMethod.POST, "/auth-service/api/auth/login", false),
            new RouteRule(HttpMethod.POST, "/auth-service/api/auth/refresh", false),
            new RouteRule(HttpMethod.POST, "/auth-service/api/auth/logout", false),
            new RouteRule(HttpMethod.POST, "/auth-service/api/auth/recover-password", false),
            new RouteRule(HttpMethod.POST, "/auth-service/api/auth/reset-password", false),

            new RouteRule(HttpMethod.GET, "/event-service/api/events", false),
            new RouteRule(HttpMethod.GET, "/event-service/api/event-categories/all", false),
            new RouteRule(HttpMethod.GET, "/event-service/api/event-modalities/all", false),

            new RouteRule(HttpMethod.GET, "^/event-service/api/events/\\d+$", true)
    );

    public static final List<RouteRule> PRIVATE_ROUTES = List.of(
            new RouteRule(HttpMethod.GET, "/event-service/api/events/my", false)
    );
}
