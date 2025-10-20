# Image that is going to be used
FROM postgres:9.6-alpine

# Maintainer
MAINTAINER Alan Ramos "alan.ramos@gmail.se"

# Define the environmental variables
ENV POSTGRES_TCP=5432
ENV POSTGRES_PASSWORD=changeme
ENV POSTGRES_HOST_AUTH_METHOD=md5

# Copy the DDL to create schema and user for application
COPY Docker-postgresql/ddl/myservice-ddl.sql /docker-entrypoint-initdb.d/

# Expose postgresql port
EXPOSE $POSTGRES_TCP