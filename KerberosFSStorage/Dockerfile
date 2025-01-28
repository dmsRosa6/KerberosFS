FROM openjdk:17

WORKDIR /app
COPY target/kerberos-filesystem-storage-1.0.0.jar app.jar
COPY src/main/resources/keystore.jks keystore.jks
COPY src/main/resources/truststore.jks truststore.jks
COPY src/main/resources/dispatcher.cer dispatcher.cer
COPY src/main/resources/storage.cer storage.cer
COPY src/main/resources/filesystem-config.properties filesystem-config.properties
COPY src/main/resources/crypto-config.properties crypto-config.properties
COPY src/main/resources/tls-config.properties tls-config.properties

EXPOSE 8083

CMD ["java", "-jar", "app.jar"]