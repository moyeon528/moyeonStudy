FROM gradle:7.2.0-jdk11

# jar파일 복사
COPY build/libs/security-1.0.jar security.jar
ENTRYPOINT ["java","-jar","security.jar"]