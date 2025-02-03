FROM openjdk:17

WORKDIR /app


COPY target/kerberos-filesystem-access-control-1.0.0.jar app.jar


COPY src/main/resources/keys.properties keys.properties
COPY src/main/resources/tls-config.properties tls-config.properties
COPY src/main/resources/access.conf access.conf

COPY src/main/resources/keystore.jks keystore.jks
COPY src/main/resources/truststore.jks truststore.jks


EXPOSE 8082

CMD ["java", "-jar", "app.jar"]
