package cue.edu.co.apigateway.security.filter;

import cue.edu.co.apigateway.constants.ServiceConstant;
import cue.edu.co.apigateway.security.handler.AuthErrorHandler;
import cue.edu.co.apigateway.security.util.JwtUtil;
import io.jsonwebtoken.JwtException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;

@Component
public class AuthenticationFilter implements GatewayFilter {

    private final JwtUtil jwtUtil;
    private final AuthErrorHandler errorHandler;
    private final String GATEWAY_INTERNAL_SECRET;

    public AuthenticationFilter(JwtUtil jwtUtil,
                                AuthErrorHandler errorHandler,
                                @Value("${app.internal.secret}")
                                String secret
                                ) {
        this.jwtUtil = jwtUtil;
        this.errorHandler = errorHandler;
        this.GATEWAY_INTERNAL_SECRET = secret;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        ServerHttpRequest.Builder requestBuilder = request.mutate()
                .header(ServiceConstant.GATEWAY_INTERNAL_HEADER, GATEWAY_INTERNAL_SECRET);

        if (Arrays.stream(ServiceConstant.PUBLIC_ENDPOINTS).anyMatch(path::startsWith)) {
            return chain.filter(exchange.mutate().request(requestBuilder.build()).build());
        }

        String authHeader = request.getHeaders().getFirst(ServiceConstant.AUTH_HEADER);
        if (authHeader == null || !authHeader.startsWith(ServiceConstant.BEARER_PREFIX)) {
            return errorHandler.handleError(exchange, HttpStatus.UNAUTHORIZED, "Missing or invalid Authorization header");
        }

        String token = authHeader.substring(ServiceConstant.BEARER_PREFIX.length());
        try {
            var claims = jwtUtil.validateToken(token);

            if (jwtUtil.isExpired(claims)) {
                return errorHandler.handleError(exchange, HttpStatus.UNAUTHORIZED, "Token expired");
            }

            ServerHttpRequest modifiedRequest = requestBuilder
                    .header("X-User-Id", String.valueOf(jwtUtil.getUserId(claims)))
                    .header("X-User-Role", jwtUtil.getRole(claims))
                    .build();

            return chain.filter(exchange.mutate().request(modifiedRequest).build());

        } catch (JwtException e) {
            return errorHandler.handleError(exchange, HttpStatus.UNAUTHORIZED, "Invalid or malformed token");
        }
    }

}