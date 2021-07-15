# FROM openjdk:8-jdk-alpine
# ARG JAR_FILE=target/*.jar
# COPY ${JAR_FILE} app.jar
# ENTRYPOINT ["java","-jar", "-Dspring.profiles.active=prod","/app.jar"]

FROM maven:3.6-openjdk-8-slim  AS build
WORKDIR /app
COPY . .

RUN mvn -f ./pom.xml clean package -DskipTests

FROM openjdk:8-jdk-alpine
WORKDIR /app
COPY --from=build /app/target/*.jar ./app.jar

ENTRYPOINT ["java","-jar","-Dspring.profiles.active=kube","app.jar"]