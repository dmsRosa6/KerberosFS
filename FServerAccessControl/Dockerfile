FROM openjdk:17

WORKDIR /app
COPY target/FServerAccessControl-1.jar app.jar
COPY src/main/resources/keystore.jks keystore.jks
COPY src/main/resources/truststore.jks truststore.jks
COPY src/main/resources/dispatcher.cer dispatcher.cer
COPY src/main/resources/access_control.cer access_control.cer
COPY src/main/resources/keys.properties keys.properties
COPY src/main/resources/access.conf access.conf
COPY src/main/resources/tls-config.properties tls-config.properties

EXPOSE 8082

CMD ["java", "-jar", "app.jar"]