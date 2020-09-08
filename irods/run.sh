#!/bin/bash

# Check postgres at startup
until PGPASSWORD=$IRODS_DB_PASS psql -h $IRODS_DB_HOST -U $IRODS_DB_USER $IRODS_DB_NAME -c "\d" 1> /dev/null 2> /dev/null;
do
  >&2 echo "Postgres is unavailable - sleeping"
  sleep 1
done

# setup SSL keys...
mkdir /etc/irods/ssl 2>/dev/null
cd /etc/irods/ssl

if [ ! -f irods.key ]; then
  openssl genrsa -out irods.key
fi

if [ ! -f irods.crt ]; then
  openssl req -new -key irods.key -out irods.csr \
    -subj "/C=NL/ST=Science Park/L=Amsterdam/O=SURFsara/OU=IT Department/CN=$IRODS_HOST"
  openssl x509 -req -days 365 -in irods.csr -signkey irods.key -out irods.crt
  rm irods.csr
fi

if [ ! -f dhparams.pem ]; then
  openssl dhparam -2 -out dhparams.pem 2048
fi

# Is it init time?
checkirods=$(ls /etc/irods/core.re 2>/dev/null)
if [ "$checkirods" == "" ]; then

    #############################
    # Install irods&friends     #
    #############################

    MYDATA="/tmp/answers"
    sudo -E /usr/local/bin/genresp.sh $MYDATA

    # Launch the installation
    sudo python /var/lib/irods/scripts/setup_irods.py < $MYDATA

    # Verify how it went
    if [ "$?" == "0" ]; then
        echo ""
        echo "iRODS INSTALLED!"
    else
        echo "Failed to install irods..."
        exit 1
    fi

    # Adjust core.re to enforce SSL handshake
    # sed -i 's/CS_NEG_DONT_CARE/CS_NEG_REQUIRE/' /etc/irods/core.re

    # Adjust default environment to enforce SSL handshake
    sed -i 's/CS_NEG_DONT_CARE/CS_NEG_REQUIRE/' /var/lib/irods/.irods/irods_environment.json
    sed -i 's/CS_NEG_REFUSE/CS_NEG_REQUIRE/'    /var/lib/irods/.irods/irods_environment.json

    # Adjust default environment.json to make use of SSL cert...
    sed -i '2i    "irods_ssl_certificate_chain_file": "/etc/irods/ssl/irods.crt", ' /var/lib/irods/.irods/irods_environment.json
    sed -i '3i    "irods_ssl_certificate_key_file": "/etc/irods/ssl/irods.key", '   /var/lib/irods/.irods/irods_environment.json
    sed -i '4i    "irods_ssl_ca_certificate_file": "/etc/irods/ssl/irods.crt", '    /var/lib/irods/.irods/irods_environment.json
    sed -i '5i    "irods_ssl_dh_params_file": "/etc/irods/ssl/dhparams.pem", '      /var/lib/irods/.irods/irods_environment.json
    sed -i '6i    "irods_ssl_verify_server": "none", '                              /var/lib/irods/.irods/irods_environment.json
    sed -i '7i    "irods_authentication_scheme": "PAM", '                           /var/lib/irods/.irods/irods_environment.json

    # make System Account for iRODS Admin
    pass=`echo $IRODS_PASS | openssl passwd -crypt -noverify -stdin`
    useradd --password $pass --shell /bin/false --no-create-home $IRODS_USER

    # add line to /etc/ldap/ldap.conf, that will allow self-signed certificates for TLS
    echo "TLS_REQCERT never"  >> /etc/ldap/ldap.conf

    if [ "$LDAP_FILTER" == "" ]; then
       $LDAP_FILTER=""
    fi

    echo "uri $LDAP_HOST"            >> /etc/ldap/ldap.conf
    echo "base $LDAP_BASE_DN"        >> /etc/ldap/ldap.conf
    echo "ldap_version 3"            >> /etc/ldap/ldap.conf
    echo "scope sub"                 >> /etc/ldap/ldap.conf
    echo "binddn $LDAP_BIND_DN"      >> /etc/ldap/ldap.conf
    echo "bindpw $LDAP_PASS"         >> /etc/ldap/ldap.conf
    echo "pam_login_attribute uid"   >> /etc/ldap/ldap.conf
    echo "pam_filter $LDAP_FILTER"   >> /etc/ldap/ldap.conf

    # Add PAM module for iRODS
    echo "auth sufficient pam_unix.so" > /etc/pam.d/irods
    echo "auth sufficient pam_python.so /pam_python/privacyidea_pam.py url=${PAM_PID_URL} prompt=privacyIDEA_Authentication sqlfile=/tmp/refill nosslverify" >> /etc/pam.d/irods
#   echo "auth sufficient pam_ldap.so config=/etc/ldap/ldap.conf" >> /etc/pam.d/irods
#   echo "auth sufficient /usr/local/lib/security/pam_otp.so [ldap=$LDAP_HOST] [basedn=$LDAP_BASE_DN] [binddn=$LDAP_BIND_DN] [passwd=$LDAP_PASS] [uid=$PAM_OTP_UID] [ttl=$PAM_OTP_TTL] [filter=($LDAP_FILTER)] [$PAM_OTP_DEBUG]" >> /etc/pam.d/irods

else
    # NO: launch irods
    echo "Already installed. Launching..."
    service irods start
fi

echo "iRODS is ready"

echo "starting syslog..."
rsyslogd

echo "Starting cron..."
printenv | sed 's/^\(.*\)$/export \1/g' | sed 's/=\(.*\)/="\1"/' > /usr/local/etc/env.sh

cron -f && tail -f /var/log/cron.log
