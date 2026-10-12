# Multi-stage Dockerfile for TraceX Spring Boot Microservice
FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /app

# Copy Maven POM and source
COPY pom.xml ./pom.xml
COPY src ./src

# Build production JAR
RUN mvn clean package -DskipTests

# Lightweight JRE runtime
FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

# Copy built artifact
COPY --from=build /app/target/tracex-backend-1.0.0.jar app.jar

ENV PORT=8080
EXPOSE 8080

# Run Spring Boot listening on Render's dynamic $PORT
ENTRYPOINT ["sh", "-c", "java -Dserver.port=${PORT:-8080} -jar app.jar"]
