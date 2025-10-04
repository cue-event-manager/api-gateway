package cue.edu.co.apigateway;

import cue.edu.co.apigateway.constants.ServiceConstant;
import cue.edu.co.apigateway.security.filter.AuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;

@Configuration
public class GatewayRoutesConfig {

    private final AuthenticationFilter jwtFilter;

    public GatewayRoutesConfig(AuthenticationFilter jwtFilter) {
        this.jwtFilter = jwtFilter;
    }

    @Bean
    public RouteLocator customRoutes(RouteLocatorBuilder builder) {
        return builder.routes()

                .route(ServiceConstant.AUTH_SERVICE,
                        r -> r.path(ServiceConstant.AUTH_BASE_PATH)
                                .filters(f -> f.stripPrefix(1).filter(jwtFilter))
                                .uri("lb://" + ServiceConstant.AUTH_SERVICE))

                .route(ServiceConstant.EVENT_SERVICE,
                        r -> r.path(ServiceConstant.EVENT_BASE_PATH)
                                .filters(f -> f.stripPrefix(1).filter(jwtFilter))
                                .uri("lb://" + ServiceConstant.EVENT_SERVICE))

                .route(ServiceConstant.ACADEMIC_SERVICE,
                        r -> r.path(ServiceConstant.ACADEMIC_BASE_PATH)
                                .filters(f -> f.stripPrefix(1).filter(jwtFilter))
                                .uri("lb://" + ServiceConstant.ACADEMIC_SERVICE))

                .build();
    }
}