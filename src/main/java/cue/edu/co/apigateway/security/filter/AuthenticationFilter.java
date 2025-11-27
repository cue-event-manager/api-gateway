package cue.edu.co.apigateway.security.filter;

import cue.edu.co.apigateway.constants.RouteConstant;
import cue.edu.co.apigateway.constants.ServiceConstant;
import cue.edu.co.apigateway.security.handler.AuthErrorHandler;
import cue.edu.co.apigateway.security.util.JwtUtil;
import cue.edu.co.apigateway.security.util.RouteMatcher;
import io.jsonwebtoken.JwtException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;


@Component
public class AuthenticationFilter implements GatewayFilter {

    private final JwtUtil jwtUtil;
    private final AuthErrorHandler errorHandler;
    private final String internalSecret;

    public AuthenticationFilter(
            JwtUtil jwtUtil,
            AuthErrorHandler errorHandler,
            @Value("${app.internal.secret}") String secret
    ) {
        this.jwtUtil = jwtUtil;
        this.errorHandler = errorHandler;
        this.internalSecret = secret;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpRequest.Builder builder = request.mutate();

        builder.header(ServiceConstant.GATEWAY_INTERNAL_HEADER, internalSecret);


        boolean isValidToken = tryAuthenticateAndEnrich(request, builder);

        ServerHttpRequest modifiedRequest = builder.build();
        ServerWebExchange modifiedExchange = exchange.mutate().request(modifiedRequest).build();

        if (isPublicRoute(request)) {
            return chain.filter(modifiedExchange);
        }

        if (!isValidToken) {
            return errorHandler.handleError(modifiedExchange, HttpStatus.UNAUTHORIZED,
                    "Access denied. Authentication required.");
        }

        return chain.filter(modifiedExchange);
    }

    /**
     * Attempts to extract, validate, and enrich the request with user headers.
     * @return true if a valid, unexpired token was found and headers were added, false otherwise.
     */
    private boolean tryAuthenticateAndEnrich(ServerHttpRequest request,
                                             ServerHttpRequest.Builder builder) {

        String authHeader = request.getHeaders().getFirst(ServiceConstant.AUTH_HEADER);
        if (authHeader == null || !authHeader.startsWith(ServiceConstant.BEARER_PREFIX)) {
            return false;
        }

        try {
            String token = authHeader.substring(ServiceConstant.BEARER_PREFIX.length());
            var claims = jwtUtil.validateToken(token);

            if (jwtUtil.isExpired(claims)) return false;

            builder.header(ServiceConstant.USER_ID_HEADER, String.valueOf(jwtUtil.getUserId(claims)));
            builder.header(ServiceConstant.USER_ROLE_HEADER, jwtUtil.getRole(claims));
            return true;

        } catch (JwtException ignored) {
            return false;
        }
    }

    private boolean isPublicRoute(ServerHttpRequest request) {

        return RouteConstant.PUBLIC_ROUTES.stream()
                .anyMatch(rule -> RouteMatcher.matches(request, rule));
    }

}