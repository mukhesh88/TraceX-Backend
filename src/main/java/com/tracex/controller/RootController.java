package com.tracex.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@CrossOrigin(origins = "*")
public class RootController {

    @GetMapping("/")
    public ResponseEntity<Map<String, Object>> root() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", "UP");
        response.put("service", "TraceX Edge-Optimized Lexical URL Forensics Engine");
        response.put("version", "1.0.0");

        Map<String, String> endpoints = new LinkedHashMap<>();
        endpoints.put("scan", "POST /api/v1/scan");
        endpoints.put("history", "GET /api/v1/history");
        endpoints.put("stats", "GET /api/v1/stats");
        endpoints.put("health", "GET /health");

        response.put("endpoints", endpoints);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        Map<String, String> status = new LinkedHashMap<>();
        status.put("status", "UP");
        return ResponseEntity.ok(status);
    }
}
