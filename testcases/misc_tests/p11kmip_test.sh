#!/bin/bash
#
# COPYRIGHT (c) International Business Machines Corp. 2020
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this software
# constitutes recipient's acceptance of CPL-1.0 terms which can be found
# in the file LICENSE file or at https://opensource.org/licenses/cpl1.0.php

# sudo -E ./p11kmip_test.sh

DIR=$(dirname "$0")

status=0


echo "** Now executing 'p11kmip_test.sh'"

P11KMIP_TMP="/tmp/p11kmip"
P11KMIP_UNIQUE_NAME="$(uname -n)-$(date +%s)"
P11KMIP_UNIQUE_NAME="${P11KMIP_UNIQUE_NAME^^}"
KMIP_CLIENT_NAME="$(echo ${P11KMIP_UNIQUE_NAME^^} | sed -r 's/[ .,;:#+*$%-]+/_/g')_CLIENT"
KMIP_CERT_ALIAS="$(echo ${P11KMIP_UNIQUE_NAME^^} | sed -r 's/[ .,;:#+*$%-]+/_/g')_CERT"

KMIP_SECRET_KEY_LABEL="remote-secret-key-${P11KMIP_UNIQUE_NAME}"
PKCS11_SECRET_KEY_LABEL="local-secret-key-${P11KMIP_UNIQUE_NAME}"
PKCS11_PUBLIC_KEY_LABEL="local-public-key-${P11KMIP_UNIQUE_NAME}"
PKCS11_PRIVATE_KEY_LABEL="local-private-key-${P11KMIP_UNIQUE_NAME}"

P11KMIP_CONF_FILE="${P11KMIP_TMP}/p11kmip.conf"

# Prepare PKCS11 variables
echo "** Setting SLOT=30 to the Softtoken unless otherwise set - 'p11kmip_test.sh'"

SLOT=${SLOT:-30}

echo "** Using Slot $SLOT with PKCS11_USER_PIN $PKCS11_USER_PIN and PKCSLIB $PKCSLIB - 'p11sak_test.sh'"

# Prepare KMIP variables

echo "** Setting KMIP_REST_URL=https://\${KMIP_IP}:19443 unless otherwise set - 'p11kmip_test.sh'"
echo "** Setting KMIP_SERVER=\${KMIP_IP}:5696 unless otherwise set - 'p11kmip_test.sh'"

echo "Dirpath: $DIR"
KMIP_CLIENT_CERT=$P11KMIP_TMP/${P11KMIP_UNIQUE_NAME}_p11kmip_client_cert.pem
KMIP_CLIENT_KEY=$P11KMIP_TMP/${P11KMIP_UNIQUE_NAME}_p11kmip_client_key.pem

KMIP_REST_URL="${KMIP_REST_URL:-https://${KMIP_IP}:19443}"
KMIP_HOSTNAME="${KMIP_SERVER:-${KMIP_IP}:5696}"

echo "** Using KMIP server $KMIP_REST_URL with KMIP_REST_USER $KMIP_REST_USER and KMIP_REST_PASSWORD ************"

mkdir -p $P11KMIP_TMP

generate_certificates() {
	openssl req -x509 -newkey rsa:4096 -keyout "$KMIP_CLIENT_KEY" -out "$KMIP_CLIENT_CERT" -nodes -days 3650 -subj '/CN=www.mydom.com/O=My Company Name LTD./C=US'
}

setup_kmip_client() {
  RETRY_COUNT=0
  LOGIN_DONE=0
  UPLOAD_CERT_DONE=0
  CREATE_CLIENT_DONE=0
  ASSIGN_CERT_DONE=0

  while true; do
		if [[ $RETRY_COUNT -gt 100 ]] ; then
			echo "error: Too many login retries"
			break
		fi
		RETRY_COUNT=$((RETRY_COUNT+1))

		if [[ $LOGIN_DONE -eq 0 ]] ; then
			# Get a login authorization ID from SKLM
			curl --fail-with-body --location --request POST "$KMIP_REST_URL/SKLM/rest/v1/ckms/login" \
				--header "Content-Type: application/json" \
				--data "{\"userid\":\"$KMIP_REST_USER\", \"password\":\"$KMIP_REST_PASSWORD\"}" \
				--insecure --silent --show-error >$P11KMIP_TMP/curl_get_login_authid_stdout 2>$P11KMIP_TMP/curl_get_login_authid_stderr
			RC=$?
			echo "rc:" $RC
			if [[ $RC -ne 0 ]] ; then
				cat $P11KMIP_TMP/curl_get_login_authid_stdout
				cat $P11KMIP_TMP/curl_get_login_authid_stderr
				break
			fi

			# Parse the response data and extract the authorization id token
			# Expected to return: {"UserAuthId":"xxxxxx"}
			AUTHID=`jq .UserAuthId $P11KMIP_TMP/curl_get_login_authid_stdout -r`
			echo "AuthID:" $AUTHID
			if [[ $LOGIN_DONE -eq 0 ]]; then
				echo "succeeded: curl_get_login_authid"
			fi
			if [[ $RC -ne 0 ]] ; then
				break
				cat $P11KMIP_TMP/curl_get_login_authid_stderr
			fi
			LOGIN_DONE=1
		fi

		# Upload the client certificate to SKLM
		if [[ $UPLOAD_CERT_DONE -eq 0 ]] ; then
			curl --fail-with-body --location --request POST "$KMIP_REST_URL/SKLM/rest/v1/filetransfer/upload/objectfiles" \
				--header "accept: application/json" --header "Content-Type: multipart/form-data" \
				--form "fileToUpload=@$KMIP_CLIENT_CERT" --form "destination=" --header "Authorization:SKLMAuth userAuthId=$AUTHID" \
				--insecure --silent --show-error >$P11KMIP_TMP/curl_upload_cert_stdout 2>$P11KMIP_TMP/curl_upload_cert_stderr
			RC=$?
			echo "rc:" $RC

			# Expected to return: {"code":"0","status":"CTGKM3465I File xxxx is uploaded.","messageId":"CTGKM3465I"}
			RC=`jq .code $P11KMIP_TMP/curl_upload_cert_stdout -r`
			MSG=`jq .status $P11KMIP_TMP/curl_upload_cert_stdout -r`
			if [[ "$RC" == "CTGKM6004E" ]]; then
				echo "warning: Login token expired, re-login and retry"
				continue
			fi
			if [[ "$MSG" == "CTGKM3466E Cannot upload the file $(basename $KMIP_CLIENT_CERT) because a file with the same name already exists on the server." ]]; then
				echo "info: Client certificate already uploaded to server"
				UPLOAD_CERT_DONE=1
				continue
			fi
			if [[ "$MSG" != "CTGKM3465I File $(basename $KMIP_CLIENT_CERT) is uploaded." ]]; then
				RC=1
				echo "error: Status not as expected"
				cat $P11KMIP_TMP/curl_upload_cert_stdout
				cat $P11KMIP_TMP/curl_upload_cert_stderr
			fi
			UPLOAD_CERT_DONE=1
			echo "succeeded: curl_upload_cert"
		fi

		# Create a client in SKLM
		if [[ $CREATE_CLIENT_DONE -eq 0 ]] ; then
			echo "clientname:" $KMIP_CLIENT_NAME

			curl --fail-with-body --location --request POST "$KMIP_REST_URL/SKLM/rest/v1/clients" \
				--header "Content-Type: application/json" \
				--data "{\"clientName\":\"$KMIP_CLIENT_NAME\"}" \
				--header "Authorization:SKLMAuth userAuthId=$AUTHID" \
				--insecure --silent --show-error >$P11KMIP_TMP/curl_create_client_stdout 2>$P11KMIP_TMP/curl_create_client_stderr
			RC=$?
			echo "rc:" $RC

			# Expected to return: {"message":"CTGKM3411I Successfully created client xxxx .","messageId":"CTGKM3411I"}
			MSG=`jq .message $P11KMIP_TMP/curl_create_client_stdout -r`
			if [[ "$MSG" == "CTGKM6004E User is not authenticated or has already logged out." ]]; then
				echo "warning: Login token expired, re-login and retry"
				continue
			fi
			if [[ "$MSG" != "CTGKM3411I Successfully created client $KMIP_CLIENT_NAME ." ]]; then
				RC=1
				echo "error: Message not as expected"
				cat $P11KMIP_TMP/curl_create_client_stdout
				cat $P11KMIP_TMP/curl_create_client_stderr
			fi
			CREATE_CLIENT_DONE=1
			echo "succeeded: curl_create_client"
		fi

		# Assign the certificate with the client
		if [[ $ASSIGN_CERT_DONE -eq 0 ]] ; then
			curl --fail-with-body --location --request PUT "$KMIP_REST_URL/SKLM/rest/v1/clients/$KMIP_CLIENT_NAME/assignCertificate" \
				--header "Content-Type: application/json" \
				--data "{\"certUseOption\":\"IMPORT_CERT\",\"certAlias\":\"$KMIP_CERT_ALIAS\",\"importPath\":\"$(basename $KMIP_CLIENT_CERT)\"}" \
				--header "Authorization:SKLMAuth userAuthId=$AUTHID" \
				--insecure --silent --show-error >$P11KMIP_TMP/curl_assign_cert_stdout 2>$P11KMIP_TMP/curl_assign_cert_stderr
			RC=$?
			echo "rc:" $RC

			# Expected to return: {"message":"CTGKM3409I Successfully assigned certificate to client.","messageId":"CTGKM3409I"}
			MSG=`jq .message $P11KMIP_TMP/curl_assign_cert_stdout -r`
			if [[ "$MSG" == "CTGKM6004E User is not authenticated or has already logged out." ]]; then
				echo "warning: Login token expired, re-login and retry"
				continue
			fi
			if [[ "$MSG" != "CTGKM3409I Successfully assigned certificate to client." ]]; then
				RC=1
				echo "error: Message not as expected"
				cat $P11KMIP_TMP/curl_assign_cert_stdout
				cat $P11KMIP_TMP/curl_assign_cert_stderr
			fi
			ASSIGN_CERT_DONE=1
			echo "succeeded: curl_assign_cert"
		fi

		break
	done
}

cleanup_kmip_client() {
  RETRY_COUNT=0
  LOGIN_DONE=0
  DELETE_CLIENT_DONE=0
  DELETE_CERT_DONE=0

  	while true; do
		if [[ $RETRY_COUNT -gt 100 ]] ; then
			echo "error: Too many login retries"
			break
		fi
		RETRY_COUNT=$((RETRY_COUNT+1))

		if [[ $LOGIN_DONE -eq 0 ]] ; then
			# Get a login authorization ID from SKLM
			curl --fail-with-body --location --request POST "$KMIP_REST_URL/SKLM/rest/v1/ckms/login" \
				--header "Content-Type: application/json" \
				--data "{\"userid\":\"$KMIP_REST_USER\", \"password\":\"$KMIP_REST_PASSWORD\"}" \
				--insecure --silent --show-error >$P11KMIP_TMP/curl_get_login_authid_stdout 2>$P11KMIP_TMP/curl_get_login_authid_stderr
			RC=$?
			echo "rc:" $RC
			if [[ $RC -ne 0 ]] ; then
				cat $P11KMIP_TMP/curl_get_login_authid_stdout
				cat $P11KMIP_TMP/curl_get_login_authid_stderr
				break
			fi

			# Parse the response data and extract the authorization id token
			# Expected to return: {"UserAuthId":"xxxxxx"}
			AUTHID=`jq .UserAuthId $P11KMIP_TMP/curl_get_login_authid_stdout -r`
			echo "AuthID:" $AUTHID
			if [[ $LOGIN_DONE -eq 0 ]]; then
				echo "succeeded: curl_get_login_authid"
			fi
			if [[ $RC -ne 0 ]] ; then
				break
				cat $P11KMIP_TMP/curl_get_login_authid_stderr
			fi
			LOGIN_DONE=1
		fi

		# Delete a client in SKLM
		if [[ $DELETE_CLIENT_DONE -eq 0 ]] ; then
			echo "clientname:" $KMIP_CLIENT_NAME

			curl --fail-with-body --location --request DELETE "$KMIP_REST_URL/SKLM/rest/v1/clients/$KMIP_CLIENT_NAME" \
				--header "Content-Type: application/json" \
				--header "Authorization:SKLMAuth userAuthId=$AUTHID" \
				--insecure --silent --show-error >$P11KMIP_TMP/curl_delete_client_stdout 2>$P11KMIP_TMP/curl_delete_client_stderr
			RC=$?
			echo "rc:" $RC

			# Expected to return: {"message":"CTGKM3411I Successfully created client xxxx .","messageId":"CTGKM3411I"}
			MSG=`jq .message $P11KMIP_TMP/curl_delete_client_stdout -r`
			if [[ "$MSG" == "CTGKM6004E User is not authenticated or has already logged out." ]]; then
				echo "warning: Login token expired, re-login and retry"
				continue
			fi
			if [[ "$MSG" != "" ]]; then
				RC=1
				echo "error: Message not as expected"
				cat $P11KMIP_TMP/curl_delete_client_stdout
				cat $P11KMIP_TMP/curl_delete_client_stderr
			fi
			DELETE_CLIENT_DONE=1
			echo "succeeded: curl_delete_client"
		fi

		# Delete the client certificate from SKLM
		if [[ $DELETE_CERT_DONE -eq 0 ]] ; then
			curl --fail-with-body --location --request DELETE "$KMIP_REST_URL/SKLM/rest/v1/certificates/$KMIP_CERT_ALIAS" \
				--header "accept: application/json" \
				--header "Authorization:SKLMAuth userAuthId=$AUTHID" \
				--insecure --silent --show-error >$P11KMIP_TMP/curl_delete_cert_stdout 2>$P11KMIP_TMP/curl_delete_cert_stderr
			RC=$?
			echo "rc:" $RC

			# Expected to return: {"code":"0","status":"CTGKM3465I File xxxx is uploaded.","messageId":"CTGKM3465I"}
			RC=`jq .code $P11KMIP_TMP/curl_delete_cert_stdout -r`
			MSG=`jq .status $P11KMIP_TMP/curl_delete_cert_stdout -r`
			if [[ "$RC" == "CTGKM6004E" ]]; then
				echo "warning: Login token expired, re-login and retry"
				continue
			fi
			if [[ "$MSG" != "CTGKM3465I File $(basename $KMIP_CLIENT_CERT) is deleted." ]]; then
				RC=1
				echo "error: Status not as expected"
				cat $P11KMIP_TMP/curl_delete_cert_stdout
				cat $P11KMIP_TMP/curl_delete_cert_stderr
			fi
			DELETE_CERT_DONE=1
			echo "succeeded: curl_delete_cert"
		fi

		break
	done
}

setup_pkcs11_keys() {
	# AES key for exporting
	p11sak import-key aes --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label $PKCS11_SECRET_KEY_LABEL --file $DIR/aes.key --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))

	# RSA keys for wrapping and importing
	p11sak import-key rsa private --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label $PKCS11_PRIVATE_KEY_LABEL --file $DIR/rsa-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	p11sak import-key rsa public --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label $PKCS11_PUBLIC_KEY_LABEL --file $DIR/rsa-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))

	echo "*** pkcs11 keys after import"
	p11sak list-key --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN
}

cleanup_pkcs11_keys() {
	# AES key for exporting
	p11sak remove-key aes --force --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label $PKCS11_SECRET_KEY_LABEL
	RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))

	# RSA keys for wrapping and importing
	p11sak remove-key rsa --force --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label $PKCS11_PRIVATE_KEY_LABEL
	RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
	p11sak remove-key rsa --force --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label $PKCS11_PUBLIC_KEY_LABEL
	RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))

	# Keys imported during test
	p11sak remove-key aes --force --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label $KMIP_SECRET_KEY_LABEL
	RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
	p11sak remove-key rsa --force --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label $KMIP_PUBLIC_KEY_LABEL
	RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
}

setup_kmip_keys() {
	curl --fail-with-body --location --request POST "$KMIP_REST_URL/SKLM/rest/v1/objects/keypair" \
		--header "accept: application/json" --header "Content-Type: application/json" \
		--data "{\"clientName\":\"$KMIP_CLIENT_NAME\", \"prefixName\":\"tst\", \"numberOfObjects\": \"1\", \"publicKeyCryptoUsageMask\":\"Wrap_Unwrap\", \"privateKeyCryptoUsageMask\":\"Wrap_Unwrap\"}" \
		--header "Authorization:SKLMAuth userAuthId=$AUTHID" \
		--insecure --silent --show-error >$P11KMIP_TMP/curl_generate_asym_keys_stdout 2>$P11KMIP_TMP/curl_generate_asym_keys_stderr
	RC_PKMIP_GENERATE=$((RC_KMIP_GENERATE + $?))

	KMIP_PUBLIC_KEY_ID=`jq .publicKeyId $P11KMIP_TMP/curl_generate_asym_keys_stdout -r`
	KMIP_PRIVATE_KEY_ID=`jq .privateKeyId $P11KMIP_TMP/curl_generate_asym_keys_stdout -r`

	curl --fail-with-body --location --request POST "$KMIP_REST_URL/SKLM/rest/v1/objects/symmetrickey" \
		--header "accept: application/json" --header "Content-Type: application/json" \
		--data "{\"clientName\":\"$KMIP_CLIENT_NAME\", \"prefixName\":\"tst\", \"numberOfObjects\": \"1\", \"cryptoUsageMask\":\"Encrypt_Decrypt\"}" \
		--header "Authorization:SKLMAuth userAuthId=$AUTHID" \
		--insecure --silent --show-error >$P11KMIP_TMP/curl_generate_sym_key_stdout 2>$P11KMIP_TMP/curl_generate_sym_key_stderr
	RC_PKMIP_GENERATE=$((RC_KMIP_GENERATE + $?))

	KMIP_SECKEY_ID=`jq .id $P11KMIP_TMP/curl_generate_sym_key_stdout -r`

	curl --fail-with-body --location --request GET "$KMIP_REST_URL/SKLM/rest/v1/objects/$KMIP_PUBLIC_KEY_ID" \
		--header "accept: application/json" --header "Content-Type: application/json" \
		--header "Authorization:SKLMAuth userAuthId=$AUTHID" \
		--insecure --silent --show-error >$P11KMIP_TMP/curl_get_pubkey_stdout 2>$P11KMIP_TMP/curl_get_pubkey_stderr
	RC_PKMIP_GENERATE=$((RC_KMIP_GENERATE + $?))

	KMIP_PUBLIC_KEY_LABEL=`jq .managedObject.alias $P11KMIP_TMP/curl_get_pubkey_stdout -r`
	KMIP_PUBLIC_KEY_LABEL=${KMIP_PUBLIC_KEY_LABEL:1:21}

	echo "*** kmip keys after creation"
	echo "**** kmip pubkey id: ${KMIP_PUBLIC_KEY_ID}"
	echo "**** kmip privkey id: ${KMIP_PRIVATE_KEY_ID}"
	echo "**** kmip pubkey label: ${KMIP_PUBLIC_KEY_LABEL}"

}

cleanup_kmip_keys() {
	curl --fail-with-body --location --request DELETE "$KMIP_REST_URL/SKLM/rest/v1/objects/${KMIP_PUBLIC_KEY_ID}" \
		--header "accept: application/json" --header "Content-Type: application/json" \
		--header "Authorization:SKLMAuth userAuthId=$AUTHID" \
		--insecure --silent --show-error >$P11KMIP_TMP/curl_delete_public_key_stdout 2>$P11KMIP_TMP/curl_delete_public_key_stderr

	if [[ $? -ne 0 ]] ;
	then
		echo "Error cleaning up KMIP public key"
		cat $P11KMIP_TMP/curl_delete_public_key_stdout
		cat $P11KMIP_TMP/curl_delete_public_key_stderr
	fi

	curl --fail-with-body --location --request DELETE "$KMIP_REST_URL/SKLM/rest/v1/objects/${KMIP_PRIVATE_KEY_ID}" \
		--header "accept: application/json" --header "Content-Type: application/json" \
		--header "Authorization:SKLMAuth userAuthId=$AUTHID" \
		--insecure --silent --show-error >$P11KMIP_TMP/curl_delete_private_key_stdout 2>$P11KMIP_TMP/curl_delete_private_key_stderr

	if [[ $? -ne 0 ]] ;
	then
		echo "Error cleaning up KMIP private key"
		cat $P11KMIP_TMP/curl_delete_private_key_stdout
		cat $P11KMIP_TMP/curl_delete_private_key_stderr
	fi

	curl --fail-with-body --location --request DELETE "$KMIP_REST_URL/SKLM/rest/v1/objects/${KMIP_SENT_WRAPKEY_UID}" \
		--header "accept: application/json" --header "Content-Type: application/json" \
		--header "Authorization:SKLMAuth userAuthId=$AUTHID" \
		--insecure --silent --show-error >$P11KMIP_TMP/curl_delete_wrapping_key_stdout 2>$P11KMIP_TMP/curl_delete_wrapping_key_stderr
	
	if [[ $? -ne 0 ]] ;
	then
		echo "Error cleaning up KMIP wrapping key"
		cat $P11KMIP_TMP/curl_delete_wrapping_key_stdout
		cat $P11KMIP_TMP/curl_delete_wrapping_key_stderr
	fi

	curl --fail-with-body --location --request DELETE "$KMIP_REST_URL/SKLM/rest/v1/objects/${KMIP_GEND_TARGKEY_ID}" \
		--header "accept: application/json" --header "Content-Type: application/json" \
		--header "Authorization:SKLMAuth userAuthId=$AUTHID" \
		--insecure --silent --show-error >$P11KMIP_TMP/curl_delete_secret_key_stdout 2>$P11KMIP_TMP/curl_delete_secret_key_stderr
	
	if [[ $? -ne 0 ]] ;
	then
		echo "Error cleaning up KMIP secret key"
		cat $P11KMIP_TMP/curl_delete_secret_key_stdout
		cat $P11KMIP_TMP/curl_delete_secret_key_stderr
	fi
}

compare_digests() {
	TEST_BASE="$1"
	TEST_STDOUT="${TEST_BASE}_stdout"

	cat "$TEST_STDOUT" | grep -A 5 "Secret Key" | grep "PKCS#11 Digest" | cut -c 22- > "${TEST_BASE}_pkcs_digest"
	cat "$TEST_STDOUT" | grep -A 5 "Secret Key" | grep "KMIP Digest" | cut -c 22- > "${TEST_BASE}_kmip_digest"

	diff -q "${TEST_BASE}_pkcs_digest" "${TEST_BASE}_kmip_digest"

	return $?
}

key_import_tests() {
	################################################################
	# Using configuration file options                             #
	################################################################

	# Build a standard configuration
	[[ -f $P11KMIP_CONF_FILE ]] && rm $P11KMIP_CONF_FILE
    echo "kmip {                                              " >> $P11KMIP_CONF_FILE
    echo "    host = \"${KMIP_HOSTNAME}\"                     " >> $P11KMIP_CONF_FILE
    echo "    tls_client_cert = \"${KMIP_CLIENT_CERT}\"       " >> $P11KMIP_CONF_FILE
    echo "    tls_client_key = \"${KMIP_CLIENT_KEY}\"         " >> $P11KMIP_CONF_FILE
    echo "                                                    " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_format = \"PKCS1\"                     " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_algorithm = \"RSA\"                    " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_size = 2048                            " >> $P11KMIP_CONF_FILE
    echo "    wrap_padding_method = \"PKCS1.5\"               " >> $P11KMIP_CONF_FILE
    echo "    wrap_hashing_algorithm = \"SHA-1\"              " >> $P11KMIP_CONF_FILE
    echo "}                                                   " >> $P11KMIP_CONF_FILE
    echo "pkcs11 {                                            " >> $P11KMIP_CONF_FILE
    echo "    slot_number = ${PKCS11_SLOT_ID}                 " >> $P11KMIP_CONF_FILE
    echo "}                                                   " >> $P11KMIP_CONF_FILE

	echo "*** Running test using configuration options"
	TEST_BASE="$P11KMIP_TMP/p11kmip_import_key_conf_test"

	P11KMIP_CONF_FILE="$P11KMIP_CONF_FILE" \ 
	p11kmip import-key \
		--send-wrapkey \
		--gen-targkey \
		--pin $PKCS11_USER_PIN  \
		--targkey-label $KMIP_SECRET_KEY_LABEL \
		--wrapkey-label $PKCS11_PUBLIC_KEY_LABEL \
		--unwrapkey-label $PKCS11_PRIVATE_KEY_LABEL \
		>"${TEST_BASE}_stdout" 2>"${TEST_BASE}_stderr"

	RC=$?
	echo "rc = $RC"
	echo "stdout:"
	cat $P11KMIP_TMP/p11kmip_import_key_conf_test_stdout

	if [[ $RC -ne 0 ]] ; then
		echo "stderr:"
		cat $P11KMIP_TMP/p11kmip_import_key_conf_test_stderr
		return
	fi

	# Store the UID of the KMIP public and secret key just created
	KMIP_GEND_TARGKEY_UID=$(cat $P11KMIP_TMP/p11kmip_import_key_conf_test_stdout | grep -A 2 "Secret Key" | tail -n 1 | cut -d . -f 9)
	KMIP_SENT_WRAPKEY_UID=$(cat $P11KMIP_TMP/p11kmip_import_key_conf_test_stdout | grep -A 2 "Public Key" | tail -n 1 | cut -d . -f 9)

	################################################################
	# Using environment variables                                  #
	################################################################

	# Fill the configuration file with bogus values
	[[ -f $P11KMIP_CONF_FILE ]] && rm $P11KMIP_CONF_FILE
    echo "kmip {                                           " >> $P11KMIP_CONF_FILE
    echo "    host = \"255.255.255.255:0\"                 " >> $P11KMIP_CONF_FILE
    echo "    tls_client_cert = \"/dev/null\"              " >> $P11KMIP_CONF_FILE
    echo "    tls_client_key = \"/dev/null\"               " >> $P11KMIP_CONF_FILE
    echo "                                                 " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_format = \"PKCS1\"                  " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_algorithm = \"RSA\"                 " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_size = 2048                         " >> $P11KMIP_CONF_FILE
    echo "    wrap_padding_method = \"PKCS1.5\"            " >> $P11KMIP_CONF_FILE
    echo "    wrap_hashing_algorithm = \"SHA-1\"           " >> $P11KMIP_CONF_FILE
    echo "}                                                " >> $P11KMIP_CONF_FILE
    echo "pkcs11 {                                         " >> $P11KMIP_CONF_FILE
    echo "    slot_number = 0                              " >> $P11KMIP_CONF_FILE
    echo "}                                                " >> $P11KMIP_CONF_FILE

	echo "*** Running test using environment variables"
	TEST_BASE="$P11KMIP_TMP/p11kmip_import_key_env_test"

	P11KMIP_CONF_FILE="$P11KMIP_CONF_FILE" \ 
	PKCS11_USER_PIN="$PKCS11_USER_PIN" \ 
	PKCS11_SLOT_ID="$PKCS11_SLOT_ID" \ 
	KMIP_HOSTNAME="$KMIP_HOSTNAME" \ 
	KMIP_CLIENT_CERT="$KMIP_CLIENT_CERT" \ 
	KMIP_CLIENT_KEY="$KMIP_CLIENT_KEY" p11kmip import-key \
		--targkey-label $KMIP_SECRET_KEY_LABEL \
		--wrapkey-label $PKCS11_PUBLIC_KEY_LABEL \
		--unwrapkey-label $PKCS11_PRIVATE_KEY_LABEL \
		>"${TEST_BASE}_stdout" 2>"${TEST_BASE}_stderr"

	echo "rc = $?"
	echo "stdout:"
	cat $P11KMIP_TMP/p11kmip_import_key_env_test_stdout

	if [[ $RC -ne 0 ]] ; then
		echo "stderr:"
		cat $P11KMIP_TMP/p11kmip_import_key_env_test_stderr
		return
	fi

	################################################################
	# Using only commandline options                               #
	################################################################

	echo "*** Running test using command line options"
	TEST_BASE="$P11KMIP_TMP/p11kmip_import_key_opt_test"

	p11kmip import-key \
		--slot $PKCS11_SLOT_ID \
		--pin $PKCS11_USER_PIN  \
		--kmip-host $KMIP_HOSTNAME \
		--kmip-client-cert $KMIP_CLIENT_CERT \
		--kmip-client-key $KMIP_CLIENT_KEY \
		--targkey-label $KMIP_SECRET_KEY_LABEL \
		--wrapkey-label $PKCS11_PUBLIC_KEY_LABEL \
		--unwrapkey-label $PKCS11_PRIVATE_KEY_LABEL \
		>"${TEST_BASE}_stdout" 2>"${TEST_BASE}_stderr"
	
	echo "rc = $?"
	echo "stdout:"
	cat $P11KMIP_TMP/p11kmip_import_key_opt_test_stdout

	if [[ $RC -ne 0 ]] ; then
		echo "stderr:"
		cat $P11KMIP_TMP/p11kmip_import_key_opt_test_stderr
		return
	fi
}

key_export_tests() {
	################################################################
	# Using configuration file options                             #
	################################################################

	# Build a standard configuration
	[[ -f $P11KMIP_CONF_FILE ]] && rm $P11KMIP_CONF_FILE
    echo "kmip {                                              " >> $P11KMIP_CONF_FILE
    echo "    host = \"${KMIP_HOSTNAME}\"                     " >> $P11KMIP_CONF_FILE
    echo "    tls_client_cert = \"${KMIP_CLIENT_CERT}\"       " >> $P11KMIP_CONF_FILE
    echo "    tls_client_key = \"${KMIP_CLIENT_KEY}\"         " >> $P11KMIP_CONF_FILE
    echo "                                                    " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_format = \"PKCS1\"                     " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_algorithm = \"RSA\"                    " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_size = 2048                            " >> $P11KMIP_CONF_FILE
    echo "    wrap_padding_method = \"PKCS1.5\"               " >> $P11KMIP_CONF_FILE
    echo "    wrap_hashing_algorithm = \"SHA-1\"              " >> $P11KMIP_CONF_FILE
    echo "}                                                   " >> $P11KMIP_CONF_FILE
    echo "pkcs11 {                                            " >> $P11KMIP_CONF_FILE
    echo "    slot_number = ${PKCS11_SLOT_ID}                 " >> $P11KMIP_CONF_FILE
    echo "}                                                   " >> $P11KMIP_CONF_FILE

	echo "*** Running test using configuration options"
	TEST_BASE="$P11KMIP_TMP/p11kmip_export_key_conf_test"

	P11KMIP_CONF_FILE="$P11KMIP_CONF_FILE" p11kmip export-key \
		--retr-wrapkey \
		--pin $PKCS11_USER_PIN  \
		--targkey-label $PKCS11_SECRET_KEY_LABEL \
		--wrapkey-label $KMIP_PUBLIC_KEY_LABEL \
		>"${TEST_BASE}_stdout" 2>"${TEST_BASE}_stderr"
	
	RC=$?
	echo "rc = $RC"
	echo "stdout:"
	cat $P11KMIP_TMP/p11kmip_export_key_conf_test_stdout

	if [[ $RC -ne 0 ]] ; then
		echo "stderr:"
		cat $P11KMIP_TMP/p11kmip_export_key_conf_test_stderr
		return
	fi

	# Store the UID of the PKCS#11 public key just retrieved
	KMIP_RETR_WRAPKEY_UID=$(cat $P11KMIP_TMP/p11kmip_export_key_conf_test_stdout | grep -A 2 "Public Key" | tail -n 1 | cut -d . -f 9)

    ################################################################
	# Using environment variables                                  #
	################################################################

	# Fill the configuration file with bogus values
	[[ -f $P11KMIP_CONF_FILE ]] && rm $P11KMIP_CONF_FILE
    echo "kmip {                                           " >> $P11KMIP_CONF_FILE
    echo "    host = \"255.255.255.255:0\"                 " >> $P11KMIP_CONF_FILE
    echo "    tls_client_cert = \"/dev/null\"              " >> $P11KMIP_CONF_FILE
    echo "    tls_client_key = \"/dev/null\"               " >> $P11KMIP_CONF_FILE
    echo "                                                 " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_format = \"PKCS1\"                  " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_algorithm = \"RSA\"                 " >> $P11KMIP_CONF_FILE
    echo "    wrap_key_size = 2048                         " >> $P11KMIP_CONF_FILE
    echo "    wrap_padding_method = \"PKCS1.5\"            " >> $P11KMIP_CONF_FILE
    echo "    wrap_hashing_algorithm = \"SHA-1\"           " >> $P11KMIP_CONF_FILE
    echo "}                                                " >> $P11KMIP_CONF_FILE
    echo "pkcs11 {                                         " >> $P11KMIP_CONF_FILE
    echo "    slot_number = 0                              " >> $P11KMIP_CONF_FILE
    echo "}                                                " >> $P11KMIP_CONF_FILE

	echo "*** Running test using environment variables"
	TEST_BASE="$P11KMIP_TMP/p11kmip_export_key_env_test"

	P11KMIP_CONF_FILE="$P11KMIP_CONF_FILE" \ 
	PKCS11_USER_PIN="$PKCS11_USER_PIN" \ 
	PKCS11_SLOT_ID="$PKCS11_SLOT_ID" \ 
	KMIP_HOSTNAME="$KMIP_HOSTNAME" \ 
	KMIP_CLIENT_CERT="$KMIP_CLIENT_CERT" \ 
	KMIP_CLIENT_KEY="$KMIP_CLIENT_KEY" \ 
	p11kmip export-key \
		--targkey-label $PKCS11_SECRET_KEY_LABEL \
		--wrapkey-label $KMIP_PUBLIC_KEY_LABEL \
		>"${TEST_BASE}_stdout" 2>"${TEST_BASE}_stderr"

	echo "rc = $?"
	echo "stdout:"
	cat $P11KMIP_TMP/p11kmip_export_key_env_test_stdout

	if [[ $RC -ne 0 ]] ; then
		echo "stderr:"
		cat $P11KMIP_TMP/p11kmip_export_key_env_test_stderr
		return
	fi

	################################################################
	# Using only commandline options                               #
	################################################################

	echo "*** Running test using command line options"
	TEST_BASE="$P11KMIP_TMP/p11kmip_export_key_opt_test"

	p11kmip export-key \
		--slot $PKCS11_SLOT_ID \
		--pin $PKCS11_USER_PIN  \
		--kmip-host $KMIP_HOSTNAME \
		--kmip-client-cert $KMIP_CLIENT_CERT \
		--kmip-client-key $KMIP_CLIENT_KEY \
		--targkey-label $PKCS11_SECRET_KEY_LABEL \
		--wrapkey-label $KMIP_PUBLIC_KEY_LABEL \
		--unwrapkey-label $PKCS11_PRIVATE_KEY_LABEL \
		>"${TEST_BASE}_stdout" 2>"${TEST_BASE}_stderr"
	
	echo "rc = $?"
	echo "stdout:"
	cat $P11KMIP_TMP/p11kmip_export_key_opt_test_stdout

	if [[ $RC -ne 0 ]] ; then
		echo "stderr:"
		cat $P11KMIP_TMP/p11kmip_export_key_opt_test_stderr
		return
	fi
}

echo "** Generating test certificates - 'p11kmip_test.sh'"

generate_certificates

echo "** Setting up KMIP client on KMIP server - 'p11kmip_test.sh'"

setup_kmip_client

echo "** Setting up remote and local test keys - 'p11kmip_test.sh'"

setup_kmip_keys

setup_pkcs11_keys

# echo "** Running key import tests - 'p11kmip_test.sh'"

# key_import_tests

echo "** Running key export tests - 'p11kmip_test.sh'"

key_export_tests

# echo "** Cleaning up remote and local test keys - 'p11kmip_test.sh'"

cleanup_kmip_keys

cleanup_pkcs11_keys

cleanup_kmip_client