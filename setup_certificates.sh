#!/bin/bash

# Directory setup
CERT_DIR="Certificates"
SERVICES=("dispatcher" "auth-service" "access-control" "storage" "client")
mkdir -p $CERT_DIR/{CA,dispatcher,auth-service,access-control,storage,client}

# Password generation
PASSWORD_FILE="passwords.txt"
declare -A PASSWORDS

echo "=== KerberosFS Certificate Passwords ===" > $PASSWORD_FILE
for service in "${SERVICES[@]}"; do
  PASSWORDS["${service}_keystore"]=$(openssl rand -base64 16)
  PASSWORDS["${service}_trustpass"]=$(openssl rand -base64 16)
  echo "${service}_keystore: ${PASSWORDS["${service}_keystore"]}" >> $PASSWORD_FILE
  echo "${service}_trustpass: ${PASSWORDS["${service}_trustpass"]}" >> $PASSWORD_FILE

done
echo "Passwords saved to $PASSWORD_FILE"

# Function to generate keystore and export certificate
generate_cert() {
  local service=$1
  local keystore_pass=${PASSWORDS["${service}_keystore"]}
  
  echo "Generating certificate for $service..."

  # Generate keystore
  keytool -genkeypair -alias $service \
    -keyalg RSA -keysize 2048 \
    -validity 365 \
    -keystore $CERT_DIR/$service/keystore.jks \
    -storepass $keystore_pass \
    -keypass $keystore_pass \
    -dname "CN=$service, OU=KerberosFS, O=YourOrg, L=YourCity, ST=YourState, C=CC"
  
  # Export certificate
  keytool -exportcert -alias $service \
    -file $CERT_DIR/$service/$service.cer \
    -keystore $CERT_DIR/$service/keystore.jks \
    -storepass $keystore_pass
}

# Generate certificates for all services
for service in "${SERVICES[@]}"; do
  generate_cert $service
done

# Function to configure truststores
configure_truststore() {
  local service=$1
  local truststore_pass=${PASSWORDS["${service}_trustpass"]}
  
  echo "Configuring truststore for $service..."

  for cert_service in "${SERVICES[@]}"; do
    if [[ "$cert_service" != "$service" ]]; then
      local cert_file="$CERT_DIR/$cert_service/$cert_service.cer"
      
      if [[ -f "$cert_file" ]]; then
        keytool -importcert -alias $cert_service \
          -file $cert_file \
          -keystore $CERT_DIR/$service/truststore.jks \
          -storepass $truststore_pass <<< "yes"
      else
        echo "Warning: Certificate for $cert_service not found! Skipping import."
      fi
    fi
  done
}

# Configure truststores after all certificates exist
for service in "${SERVICES[@]}"; do
  configure_truststore $service

done

# Set file permissions
echo "Setting file permissions..."
chmod 600 $CERT_DIR/*/*.jks
chmod 644 $CERT_DIR/*/*.cer

# Verification
echo "Verifying certificates and truststores..."
for service in "${SERVICES[@]}"; do
  echo "=== $service Keystore ==="
  keytool -list -v -keystore $CERT_DIR/$service/keystore.jks \
    -storepass ${PASSWORDS["${service}_keystore"]} | grep 'Alias name:'
  
  echo "=== $service Truststore ==="
  keytool -list -v -keystore $CERT_DIR/$service/truststore.jks \
    -storepass ${PASSWORDS["${service}_trustpass"]} | grep 'Alias name:'

done

echo "Certificate setup complete!"
