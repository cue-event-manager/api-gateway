package cue.edu.co.apigateway.models;

import org.springframework.http.HttpMethod;

public record PublicRoute(String pattern, HttpMethod method) {}
