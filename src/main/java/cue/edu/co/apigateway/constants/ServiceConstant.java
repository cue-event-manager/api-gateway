package cue.edu.co.apigateway.constants;

public final class ServiceConstant {
    private ServiceConstant() {}

    public static final String AUTH_HEADER = "Authorization";
    public static final String USER_ID_HEADER = "X-User-Id";
    public static final String USER_ROLE_HEADER = "X-User-Role";
    public static final String GATEWAY_INTERNAL_HEADER = "X-Gateway-Secret";

    public static final String BEARER_PREFIX = "Bearer ";

    public static final String AUTH_SERVICE = "cue-event-manager-auth-service";
    public static final String EVENT_SERVICE = "cue-event-manager-event-service";
    public static final String ACADEMIC_SERVICE = "cue-event-manager-academic-service";
    public static final String SPACE_SERVICE = "cue-event-manager-space-service";
    public static final String FILE_SERVICE = "cue-event-manager-file-service";

    public static final String AUTH_BASE_PATH = "/auth-service/**";
    public static final String EVENT_BASE_PATH = "/event-service/**";
    public static final String ACADEMIC_BASE_PATH = "/academic-service/**";
    public static final String SPACE_BASE_PATH = "/space-service/**";
    public static final String FILE_BASE_PATH = "/file-service/**";
}