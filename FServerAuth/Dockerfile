FROM openjdk:17

WORKDIR /app
COPY target/FServerAuth-1.jar app.jar
COPY src/main/resources/keystore.jks keystore.jks
COPY src/main/resources/truststore.jks truststore.jks
COPY src/main/resources/dispatcher.cer dispatcher.cer
COPY src/main/resources/authentication.cer authentication.cer
COPY src/main/resources/crypto-config.properties crypto-config.properties
COPY src/main/resources/users.txt users.txt
COPY src/main/resources/tls-config.properties tls-config.properties

EXPOSE 8081

CMD ["java", "-jar", "app.jar"]