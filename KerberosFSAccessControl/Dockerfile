FROM openjdk:17

WORKDIR /app


# Copy the built JAR file
COPY target/kerberos-filesystem-access-control-1.0.0.jar app.jar


# Copy only relevant certificates and configuration files
COPY src/main/resources/keys.properties keys.properties
COPY src/main/resources/tls-config.properties tls-config.properties

COPY src/main/resources/keystore.jks keystore.jks
COPY src/main/resources/truststore.jks truststore.jks
COPY src/main/resources/access-control.cer access-control.cer

EXPOSE 8082

CMD ["java", "-jar", "app.jar"]
