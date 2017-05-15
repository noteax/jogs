FROM openjdk:8

ENV POSTGREST_VERSION 0.4.1.0

RUN apt-get update && \
    apt-get install -y tar xz-utils wget libpq-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# install postgrest
RUN wget http://github.com/begriffs/postgrest/releases/download/v${POSTGREST_VERSION}/postgrest-${POSTGREST_VERSION}-ubuntu.tar.xz && \
    tar --xz -xvf postgrest-${POSTGREST_VERSION}-ubuntu.tar.xz && \
    mv postgrest /usr/local/bin/postgrest && \
    rm postgrest-${POSTGREST_VERSION}-ubuntu.tar.xz

# install flyway
RUN wget http://repo1.maven.org/maven2/org/flywaydb/flyway-commandline/3.2.1/flyway-commandline-3.2.1.zip && \
    unzip /flyway-commandline-3.2.1.zip && \
    rm /flyway-commandline-3.2.1.zip && \
    mv /flyway-3.2.1 /flyway && \
    ln -s /flyway/flyway /usr/local/bin/flyway

# add migrations
ADD migrations /migrations

# add waiter
ADD wait-for-it.sh /wait-for-it.sh
RUN chmod +x /wait-for-it.sh

# configure postgrest
ADD postgrest.conf /etc/postgrest.conf

# wait for postgres/start flyway/postgrest
CMD /wait-for-it.sh db:5432 -t 30 && \
    flyway -url=jdbc:postgresql://db:5432/postgres -user=postgres -password=pgpassword -locations=filesystem:/migrations migrate && \
    exec postgrest /etc/postgrest.conf

EXPOSE 3000
