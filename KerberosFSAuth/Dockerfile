FROM openjdk:17

WORKDIR /app

# Copy the built JAR file
COPY target/kerberos-filesystem-auth-1.0.0.jar app.jar

# Copy only relevant certificates and configuration files
COPY src/main/resources/crypto-config.properties crypto-config.properties
COPY src/main/resources/users.txt users.txt
COPY src/main/resources/tls-config.properties tls-config.properties

COPY src/main/resources/keystore.jks keystore.jks
COPY src/main/resources/truststore.jks truststore.jks
COPY src/main/resources/auth-service.cer auth-service.cer

EXPOSE 8081

CMD ["java", "-jar", "app.jar"]
