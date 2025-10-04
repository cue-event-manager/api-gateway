package cue.edu.co.apigateway.constants;

public final class ServiceConstant {
    private ServiceConstant() {}

    public static final String AUTH_SERVICE = "cue-event-manager-auth-service";
    public static final String EVENT_SERVICE = "event-service";
    public static final String ACADEMIC_SERVICE = "academic-service";

    public static final String AUTH_BASE_PATH = "/auth-service/**";
    public static final String EVENT_BASE_PATH = "/event-service/**";
    public static final String ACADEMIC_BASE_PATH = "/academic-service/**";

    public static final String GATEWAY_INTERNAL_HEADER = "X-Gateway-Secret";

    public static final String AUTH_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";

    public static final String[] PUBLIC_ENDPOINTS = {
            "/api/auth/login",
    };

}