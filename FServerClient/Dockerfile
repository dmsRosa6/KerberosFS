FROM openjdk:17

WORKDIR /app
COPY target/Client-1.jar app.jar
COPY src/main/resources/truststore.jks truststore.jks
COPY src/main/resources/dispatcher.cer dispatcher.cer

EXPOSE 8084

CMD ["java", "-jar", "app.jar"]