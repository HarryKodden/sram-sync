FROM ubuntu:16.04
MAINTAINER Harry Kodden <harry.kodden@surfnet.nl>

ARG IRODS_USER
ARG IRODS_SERVICE_PORT
ARG IRODS_CONTROL_PORT
ARG IRODS_RANGE_FROM
ARG IRODS_RANGE_TILL

ENV IRODS_USER "${IRODS_USER}"
ENV IRODS_SERVICE_PORT "${IRODS_SERVICE_PORT}"
ENV IRODS_CONTROL_PORT "${IRODS_CONTROL_PORT}"
ENV IRODS_RANGE_FROM "${IRODS_RANGE_FROM}"
ENV IRODS_RANGE_TILL "${IRODS_RANGE_TILL}"

ENV TERM xterm-256color

# INSTALL GENERIC...
RUN apt-get update && apt-get install -y wget git apt-transport-https sudo vim --fix-missing

# INSTALL IRODS
ENV IRODS_VERSION 4.2.2

RUN apt-get install -y jq libxml2 \
    && wget -qO - https://packages.irods.org/irods-signing-key.asc | apt-key add - \
    && echo "deb [arch=amd64] https://packages.irods.org/apt/ trusty main" \
    > /etc/apt/sources.list.d/renci-irods.list \
     && apt-get update && apt-get install -y \
    irods-database-plugin-postgres=$IRODS_VERSION \
    irods-runtime=$IRODS_VERSION  \
    irods-icommands=$IRODS_VERSION  \
    irods-server=$IRODS_VERSION

# INSTALL PAM_OTP
RUN apt-get install -y build-essential autoconf shtool libpam-dev libcurl4-gnutls-dev libgcrypt20 libgcrypt20-dev libldap2-dev ldap-utils
RUN git clone https://github.com/HarryKodden/pam_otp.git
RUN cd pam_otp && ln -s /usr/bin/shtool . && autoconf && ./configure && make && make install && make test && make clean

# INSTALL LDAP SYNC
RUN apt-get install -y python-pip libsasl2-dev cron
RUN python -m pip install python-ldap
ADD crontab /etc/cron.d/sync-cron
RUN chmod 0644 /etc/cron.d/sync-cron
RUN touch /var/log/cron.log

VOLUME /var/lib/irods

#EXPOSE $IRODS_SERVICE_PORT $IRODS_CONTROL_PORT $IRODS_RANGE_FROM-$IRODS_RANGE_TILL
EXPOSE $IRODS_SERVICE_PORT 

ADD genresp.sh /usr/local/bin/genresp.sh
ADD run.sh /usr/local/bin/run.sh

RUN chmod a+x /usr/local/bin/*.sh

RUN apt-get update && apt-get install -y rsyslog locales
RUN locale-gen en_US.UTF-8
RUN update-locale

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libpam-ldap

RUN git clone https://github.com/privacyidea/pam_python.git
RUN cd pam_python && pip install -r requirements.txt

RUN apt-get install -y libpam-python sqlite3

CMD ["/usr/local/bin/run.sh"]