#!/bin/bash

if [ $# -ne 1 ]
then
        echo "Usage: $0 <signcert>
        exit 1
fi


env_setup()
{
	dir=$HOME/opt/certs
	mkdir -p $HOME/opt/certs
	cd $HOME/opt/certs/
}


ca_setup()
{
	echo "generating a root keypair"
	openssl genrsa -des3 -out myCA.key -passout pass:Stream@123 2048
	echo "generating a root cert"
	openssl req -x509 -new -nodes -key myCA.key -sha256 -days 1825 -out myCA.pem  -passin pass:Stream@123 -subj "/C=IN/ST=MH/L=PNQ/O=StreamSets/OU=SDC/CN=caauth"
	### Adding ca cert to mac keychain####
  ### Remove this line if you wish not to add the cert to mac keychain###
  sudo security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" myCA.pem
	keytool -importcert -noprompt -file myCA.pem -trustcacerts  -alias myCA -storepass Stream@123 -keystore truststore.jks
		echo "authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:TRUE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = *
DNS.2 = `hostname -f | awk '{print tolower($0)}'`
DNS.3 = localhost
DNS.4 = `hostname -f`
DNS.5 = `ifconfig | grep -w inet | awk 'FNR == 2 {print $2}'`" > sdc.ext
echo "signing a generated host/service cert"
}


csr_cert_setup()

{
	echo "generating a keystore and host/service cert"
	echo -ne '\n' |keytool -genkeypair -alias $(hostname -f) -keyalg RSA -keystore $(hostname -f).jks -keysize 2048 -dname "CN=$(hostname -f),OU=support,O=streamsets,L=PNQ,ST=MH,C=IN" -storepass Stream@123
	echo "generating a CSR"
	keytool -certreq -alias $(hostname -f) -keystore $(hostname -f).jks -file $(hostname -f).csr  -ext EKU=serverAuth,clientAuth -storepass Stream@123
    echo "signing a host/service cert"
	openssl x509 -req -in $(hostname -f).csr -CA myCA.pem -CAkey myCA.key -CAcreateserial -out $(hostname -f).crt -days 825  -passin pass:Stream@123 -sha256 -extfile sdc.ext

	keytool -importcert -noprompt -file $(hostname -f).crt -trustcacerts -alias $(hostname -f) -storepass Stream@123 -keystore truststore.jks
	cat myCA.pem >> $(hostname -f).crt
	keytool -importcert -alias $(hostname -f) -file $(hostname -f).crt -keystore $(hostname -f).jks -storepass Stream@123

	 
}

env_setup
ca_setup
csr_cert_setup
