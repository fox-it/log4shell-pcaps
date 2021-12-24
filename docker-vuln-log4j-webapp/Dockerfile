FROM openjdk:8u181-jdk-alpine

WORKDIR /app

# Download vulnerable log4j
RUN wget https://repo.maven.apache.org/maven2/org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar
RUN wget https://repo.maven.apache.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar

# base64 decode functionality for basic auth
RUN wget https://repo1.maven.org/maven2/commons-codec/commons-codec/1.10/commons-codec-1.10.jar

# For logging TLS secrets we use jSSLKeyLog agent
RUN wget https://github.com/jsslkeylog/jsslkeylog/releases/download/v1.3.0/jSSLKeyLog-1.3.zip
RUN unzip jSSLKeyLog-1.3.zip

# Copy App and log4j configuration for debug output to stdout
COPY App.java /app/
COPY log4j2.xml /app/

# Install tcpdump for pcap creation
RUN apk update
RUN apk add tcpdump

# Compile App.java
RUN javac -cp log4j-api-2.14.1.jar:log4j-core-2.14.1.jar:commons-codec-1.10.jar App.java

# Run App
CMD java -javaagent:jSSLKeyLog.jar=/tmp/sslkeylog.txt -Dlog4j.configurationFile=/app/log4j2.xml -Dcom.sun.jndi.rmi.object.trustURLCodebase=true -cp .:log4j-api-2.14.1.jar:log4j-core-2.14.1.jar:commons-codec-1.10.jar App
