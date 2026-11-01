FROM registry.galaxy.local:30500/base/eclipse-temurin:17-jre
ARG JAR_FILE
ENV APP_PORT=8080
ENV JAVA_OPTS=""
WORKDIR /app
COPY ${JAR_FILE} app.jar
EXPOSE ${APP_PORT}
ENTRYPOINT ["sh","-c","exec java -XX:+UseContainerSupport -XX:MaxRAMPercentage=75 ${JAVA_OPTS:-} -jar /app/app.jar"]
