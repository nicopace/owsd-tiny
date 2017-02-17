#/bin/sh

make_certs () 
{
	mkdir "$1"/

	echo Creating root CA
	openssl genrsa >"$1"/gateway-root-CA-key.pem
	openssl req -new -subj '/CN=root CA for gateways' -key "$1"/gateway-root-CA-key.pem -x509 -out "$1"/gateway-root-CA-cert.pem -days 3000

	echo Creating master CA
	openssl genrsa >"$1"/master-CA-key.pem
	openssl req -new -subj '/CN=owsd CA for master gateways' -key "$1"/master-CA-key.pem -x509 \
		-out "$1"/master-CA-cert.pem -days 3000
		#| openssl x509 -req -CAcreateserial -CA "$1"/gateway-root-CA-cert.pem -CAkey "$1"/gateway-root-CA-key.pem -extfile /etc/ssl/openssl.cnf -extensions v3_ca -out "$1"/master-CA-cert.pem -days 3000

	echo

	#echo Concatenating CAs
	#cat "$1"/master-CA-cert.pem "$1"/gateway-root-CA-cert.pem > "$1"/gateway-CAs.pem

	echo Creating cert for master
	openssl genrsa >"$1"/master1-key.pem
	openssl req -new -subj '/CN=master1' -key "$1"/master1-key.pem \
		| openssl x509 -days 500 -req -CAcreateserial -CA "$1"/master-CA-cert.pem -CAkey "$1"/master-CA-key.pem -out "$1"/master1-cert.pem
	echo -en "Done:\t"
	ls "$1"/master1*.pem
	echo

	echo Creating cert for repeater
	openssl genrsa > "$1"/repeater1-key.pem
	openssl req -new -subj '/CN=repeater1' -key "$1"/repeater1-key.pem \
		| openssl x509 -days 500 -req -CAcreateserial -CA "$1"/gateway-root-CA-cert.pem -CAkey "$1"/gateway-root-CA-key.pem -out "$1"/repeater1-cert.pem
	echo -en "Done:\t"
	ls "$1"/repeater1*.pem
	echo

	echo Done
	cat <<-EOF
	To configure networked ubus do:
	- on the repeater device, enable HTTPS on some port with $1/repeater1*.pem for
	  the cert+key pair and $1/master-CA.pem as the CA file
	- on the master device, use $1/master1*pem as the cert+key pair and
	  $1/gateway-root-CA-cert.pem as CA

	EOF
}

set -e
make_certs "$@"
