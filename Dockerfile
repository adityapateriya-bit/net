# ---- build stage: compile with the full JDK ----
FROM eclipse-temurin:21-jdk AS build
WORKDIR /app
COPY src ./src
COPY build.sh .
RUN sh build.sh

# ---- run stage: small JRE-only image ----
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /app/build/netscan.jar .
# Cloud deployments refuse to scan private/internal addresses.
ENV NETSCAN_PUBLIC_MODE=true
ENV PORT=8080
EXPOSE 8080
CMD ["java", "-jar", "netscan.jar"]
