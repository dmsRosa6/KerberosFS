FROM openjdk:17

WORKDIR /app

# Copy the built JAR file
COPY target/kerberos-filesystem-auth-1.0.0.jar app.jar


# Copy only relevant certificates and configuration files

EXPOSE 8084

CMD ["java", "-jar", "app.jar"]