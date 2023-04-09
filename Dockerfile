FROM bellsoft/liberica-openjdk-alpine:17.0.3.1-2
COPY /target/mymessenger-backend-0.0.1-SNAPSHOT.jar /mymessenger-backend.jar
CMD ["java", "-jar", "/mymessenger-backend.jar"]