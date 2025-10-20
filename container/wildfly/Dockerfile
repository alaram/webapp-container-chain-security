# Image that is going to be used
FROM jboss/wildfly:24.0.0.Final

# Setting Timezone and project encoding
ENV TZ Europe/Stockholm
ENV LANG en_US.UTF-8

# Define binaries versions
ENV POSTGRESQL_VERSION=9.4-1201
ENV ACTIVE_RAR_VERSION=5.16.3
ENV HAZELCAST_MANCENTER_VERSION=4.2021.06

# Define binaries for deployment
ENV POSTGRESQL postgresql-$POSTGRESQL_VERSION
ENV ACTIVE_RAR activemq-rar-$ACTIVE_RAR_VERSION
ENV HAZELCASTMANCENTER hazelcast-management-center-$HAZELCAST_MANCENTER_VERSION

# Define communications ports
ENV WILDFLY_TCP=8080 WILDFLY_UI=9990

# Maintainer
MAINTAINER Alan Ramos "alan.ramos@gmail.se"

# Perform the appropiate configuration to remove WARNS and load extra packages/modules
COPY ./Docker-wildfly/bin/standalone.conf $JBOSS_HOME/bin/
COPY ./Docker-wildfly/standalone/configuration/env_st/standalone.xml $JBOSS_HOME/standalone/configuration/
COPY ./Docker-wildfly/modules/system/layers/base/org/jboss/resteasy/resteasy-jaxb-provider/main/module.xml $JBOSS_HOME/modules/system/layers/base/org/jboss/resteasy/resteasy-jaxb-provider/main/
COPY ./Docker-wildfly/modules/system/layers/base/org/jboss/resteasy/resteasy-multipart-provider/main/module.xml $JBOSS_HOME/modules/system/layers/base/org/jboss/resteasy/resteasy-multipart-provider/main/

# Perform the appropiate deployments for myservice and other applications
COPY ./Docker-wildfly/deployments/$HAZELCASTMANCENTER.jar $JBOSS_HOME/standalone/deployments/
COPY ./Docker-wildfly/deployments/$ACTIVE_RAR.rar $JBOSS_HOME/standalone/deployments/
COPY ./myservice-batch/target/*.war $JBOSS_HOME/standalone/deployments/

# Create the appropiate directory for datasource dependency
# Copy datasource depedency and datasource configuration
RUN mkdir $JBOSS_HOME/modules/org/
RUN mkdir $JBOSS_HOME/modules/org/postgres/
RUN mkdir $JBOSS_HOME/modules/org/postgres/main
COPY ./Docker-wildfly/modules/org/postgres/main/module.xml $JBOSS_HOME/modules/org/postgres/main
COPY ./Docker-wildfly/modules/org/postgres/main/$POSTGRESQL.jdbc4.jar $JBOSS_HOME/modules/org/postgres/main

# Create management user for Wildfly
RUN $JBOSS_HOME/bin/add-user.sh admin Admin#12345 --silent

# Expose communication ports
EXPOSE $WILDFLY_TCP $WILDFLY_UI

# Running the process
CMD ["/opt/jboss/wildfly/bin/standalone.sh", "-b", "0.0.0.0", "-bmanagement", "0.0.0.0"]