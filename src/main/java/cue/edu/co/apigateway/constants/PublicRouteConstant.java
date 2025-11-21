package cue.edu.co.apigateway.constants;

import cue.edu.co.apigateway.models.PublicRoute;
import org.springframework.http.HttpMethod;

import java.util.List;

public class PublicRouteConstant {
    public static final List<PublicRoute> ROUTES = List.of(
            new PublicRoute("/auth-service/api/auth/login", HttpMethod.POST),
            new PublicRoute("/auth-service/api/auth/refresh", HttpMethod.POST),
            new PublicRoute("/auth-service/api/auth/logout", HttpMethod.POST),
            new PublicRoute("/auth-service/api/auth/recover-password", HttpMethod.POST),
            new PublicRoute("/auth-service/api/auth/reset-password", HttpMethod.POST),

            new PublicRoute("/event-service/api/events", HttpMethod.GET),
            new PublicRoute("/event-service/api/event-categories/all", HttpMethod.GET),
            new PublicRoute("/event-service/api/event-modalities/all", HttpMethod.GET)
    );
}
