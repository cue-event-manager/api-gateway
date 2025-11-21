package cue.edu.co.apigateway.security.filter;

import cue.edu.co.apigateway.constants.PublicRouteConstant;
import cue.edu.co.apigateway.constants.ServiceConstant;
import cue.edu.co.apigateway.security.handler.AuthErrorHandler;
import cue.edu.co.apigateway.security.util.JwtUtil;
import io.jsonwebtoken.JwtException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpMethod;
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

        ServerHttpRequest.Builder builder = request.mutate()
                .header(ServiceConstant.GATEWAY_INTERNAL_HEADER, internalSecret);

        if (isPublicRoute(request)) {
            return chain.filter(exchange.mutate().request(builder.build()).build());
        }

        String authHeader = request.getHeaders().getFirst(ServiceConstant.AUTH_HEADER);
        if (authHeader == null || !authHeader.startsWith(ServiceConstant.BEARER_PREFIX)) {
            return errorHandler.handleError(exchange, HttpStatus.UNAUTHORIZED,
                    "Missing or invalid Authorization header");
        }

        String token = authHeader.substring(ServiceConstant.BEARER_PREFIX.length());

        try {
            var claims = jwtUtil.validateToken(token);

            if (jwtUtil.isExpired(claims)) {
                return errorHandler.handleError(exchange, HttpStatus.UNAUTHORIZED, "Token expired");
            }

            ServerHttpRequest modifiedRequest = builder
                    .header(ServiceConstant.USER_ID_HEADER, String.valueOf(jwtUtil.getUserId(claims)))
                    .header(ServiceConstant.USER_ROLE_HEADER, jwtUtil.getRole(claims))
                    .build();

            return chain.filter(exchange.mutate().request(modifiedRequest).build());

        } catch (JwtException e) {
            return errorHandler.handleError(exchange, HttpStatus.UNAUTHORIZED, "Invalid or malformed token");
        }
    }

    private boolean isPublicRoute(ServerHttpRequest request) {
        String path = request.getURI().getPath();
        HttpMethod method = request.getMethod();

        return PublicRouteConstant.ROUTES.stream()
                .anyMatch(r -> r.pattern().equals(path) && r.method().equals(method));
    }
}