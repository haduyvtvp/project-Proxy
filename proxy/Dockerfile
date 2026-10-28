
FROM maven:3.9.9-eclipse-temurin-17 AS build

WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN mvn clean package

FROM eclipse-temurin:17-jre

WORKDIR /app

COPY --from=build /app/target/secure-proxy-1.0.0.jar app.jar

EXPOSE 8888

CMD ["java", "-jar", "app.jar"]
