package cue.edu.co.apigateway.constants;

import cue.edu.co.apigateway.models.RouteRule;
import org.springframework.http.HttpMethod;

import java.util.List;

public class PublicRouteConstant {
    public static final List<RouteRule> ROUTES = List.of(
            new RouteRule("/auth-service/api/auth/login", HttpMethod.POST),
            new RouteRule("/auth-service/api/auth/refresh", HttpMethod.POST),
            new RouteRule("/auth-service/api/auth/logout", HttpMethod.POST),
            new RouteRule("/auth-service/api/auth/recover-password", HttpMethod.POST),
            new RouteRule("/auth-service/api/auth/reset-password", HttpMethod.POST),

            new RouteRule("/event-service/api/events", HttpMethod.GET),
            new RouteRule("/event-service/api/event-categories/all", HttpMethod.GET),
            new RouteRule("/event-service/api/event-modalities/all", HttpMethod.GET)
    );
}
