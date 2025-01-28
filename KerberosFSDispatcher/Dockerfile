FROM openjdk:17

WORKDIR /app
COPY target/kerberos-filesystem-dispatcher-1.0.0.jar app.jar
COPY src/main/resources/ .

EXPOSE 8080

CMD ["java", "-jar", "app.jar"]