# ⚡ TraceX Backend — Lexical URL Forensics & ONNX ML Engine

[![Java](https://img.shields.io/badge/Java-17-ED8B00?style=flat-square&logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.2.5-6DB33F?style=flat-square&logo=spring-boot&logoColor=white)](https://spring.io/projects/spring-boot)
[![ONNX Runtime](https://img.shields.io/badge/ONNX_Runtime-1.18.0-blue?style=flat-square&logo=onnx)](https://onnxruntime.ai/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

> **TraceX Backend**: An edge-optimized, real-time phishing detection microservice that inspects incoming URLs purely through static structural, statistical, and lexical features with sub-millisecond ONNX Runtime machine learning inference—before any DNS resolution or HTTP request is performed.

---

## ⚡ Core Architecture

- **Zero-Network Lexical Feature Extraction:** Extracts 12 mathematical & structural signals purely from the URL string in `<0.5ms`:
  1. `url_length`: Total character length
  2. `hostname_length`: Character length of parsed host
  3. `path_length`: Length of URI path
  4. `shannon_entropy`: Character Shannon entropy ($H(X) = -\sum P(x) \log_2 P(x)$)
  5. `subdomain_count`: Dot-separated labels count
  6. `has_ip_address`: Raw IPv4/IPv6 flag
  7. `is_punycode`: IDN homograph flag (`xn--`)
  8. `symbol_count_at`: Redirection indicator count (`@`)
  9. `symbol_count_hyphen`: Hyphen count in hostname
  10. `suspicious_keyword_flag`: Security token distribution (`login`, `verify`, `banking`, `secure`, `wallet`)
  11. `tld_risk_weight`: Abuse TLD weight scoring (`.xyz`, `.top`, `.buzz`, `.tk`)
  12. `digit_to_letter_ratio`: Numeric ratio across string
- **Low-Latency ONNX Inference:** Thread-safe singleton service initializing `OrtEnvironment` and `OrtSession` loading `model.onnx` with automatic heuristic fallback.
- **Root Health Endpoints:** Pre-configured with `@GetMapping("/")` and `@GetMapping("/health")` to prevent cloud 404 Whitelabel errors.
- **Global CORS Enabled:** Fully supports cross-origin requests from Vercel preview & production deployments as well as browser extensions.

---

## 📡 REST API Contracts

### 1. Root & Health
```http
GET /
GET /health
```
**Response:**
```json
{
  "status": "UP",
  "service": "TraceX Edge-Optimized Lexical URL Forensics Engine",
  "version": "1.0.0",
  "endpoints": {
    "scan": "POST /api/v1/scan",
    "history": "GET /api/v1/history",
    "stats": "GET /api/v1/stats",
    "health": "GET /health"
  }
}
```

### 2. Scan URL (Inference)
```http
POST /api/v1/scan
Content-Type: application/json

{
  "url": "https://secure-login.apple-support-verify.com/auth"
}
```
**Response:**
```json
{
  "url": "https://secure-login.apple-support-verify.com/auth",
  "status": "MALICIOUS",
  "riskScore": 0.825,
  "inferenceLatencyMs": 0.33,
  "features": {
    "shannonEntropy": 4.281,
    "isPunycode": false,
    "subdomainCount": 1,
    "flaggedKeywords": ["login", "verify", "secure", "support", "auth"]
  },
  "timestamp": "2026-10-11T15:25:02.803Z",
  "fallbackUsed": false
}
```

### 3. History & Telemetry
- `GET /api/v1/history?page=0&size=20`: Paginated audit log of prior scans.
- `GET /api/v1/stats`: Aggregate threat telemetry (total, malicious ratio, average JVM latency).

---

## 🐳 Docker & Cloud Deployment (Render)

This repository includes a multi-stage production `Dockerfile` at root:

```bash
# Build Docker image
docker build -t tracex-backend .

# Run container on port 8080
docker run -p 8080:8080 -e PORT=8080 tracex-backend
```

### Deploying to Render:
1. Connect `mukhesh88/TraceX-Backend` as a **Web Service**.
2. Environment: **Docker**
3. Docker Context: `.`
4. Dockerfile Path: `./Dockerfile`
5. Plan: **Free** ($0/month)

---

## 💻 Local Execution (Maven)

```bash
# Package and run Spring Boot
mvn clean package -DskipTests
java -jar target/tracex-backend-1.0.0.jar
```

Server listens on [http://localhost:8080](http://localhost:8080).

---

## 🔗 Related Repositories

- **Frontend & Browser Extension:** [TraceX-Frontend](https://github.com/mukhesh88/TraceX-Frontend) (Next.js, React, Tailwind CSS)
- **Live Backend API:** `https://tracex-backend-s6kq.onrender.com`
