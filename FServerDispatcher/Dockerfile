FROM openjdk:17

WORKDIR /app
COPY target/FServer-1.jar app.jar
COPY src/main/resources/ .
COPY src src/
COPY pom.xml pom.xml

EXPOSE 8080

CMD ["java", "-jar", "app.jar"]