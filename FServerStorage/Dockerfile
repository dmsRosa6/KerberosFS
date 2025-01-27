FROM maven:3.8.1-openjdk-17 as build

WORKDIR /app

COPY src src
COPY pom.xml pom.xml
RUN mvn package

FROM openjdk:17

COPY --from=build /app/target/FServerStorage-1-jar-with-dependencies.jar /app/app.jar
COPY src/main/resources/keystore.jks /app/keystore.jks
COPY src/main/resources/truststore.jks /app/truststore.jks
COPY src/main/resources/dispatcher.cer /app/dispatcher.cer
COPY src/main/resources/storage.cer /app/storage.cer
COPY src/main/resources/filesystem-config.properties /app/filesystem-config.properties
COPY src/main/resources/dropbox-config.properties /app/dropbox-config.properties
COPY src/main/resources/crypto-config.properties /app/crypto-config.properties
COPY src/main/resources/tls-config.properties /app/tls-config.properties

WORKDIR /app
EXPOSE 8083

CMD ["java", "-jar", "app.jar", "org.example.StorageService"]