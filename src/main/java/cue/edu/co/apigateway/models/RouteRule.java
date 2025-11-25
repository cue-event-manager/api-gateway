package cue.edu.co.apigateway.models;

import org.springframework.http.HttpMethod;

public record RouteRule(
        HttpMethod method,
        String pattern,
        boolean regex
) {}