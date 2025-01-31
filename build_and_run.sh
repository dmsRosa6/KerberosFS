#!/bin/bash

# Helper function to check for errors
handle_error() {
    if [ $? -ne 0 ]; then
        echo "Error occurred: $1"
        exit 1
    fi
}

# Define paths
CERTS_SOURCE="Certificates"
SERVICES_DIR=("storage" "access-control" "auth-service" "dispatcher")
services=("KerberosFSStorage" "KerberosFSAccessControl" "KerberosFSAuth" "KerberosFSDispatcher")

# Copy certificates to the respective services before building
echo "Copying certificates to service directories..."
for i in "${!SERVICES_DIR[@]}"; do
    service_src=${SERVICES_DIR[$i]}
    service_dest=${services[$i]}
    mkdir -p "$service_dest/src/main/resources/"
    cp -r "$CERTS_SOURCE/$service_src/"* "$service_dest/src/main/resources/"
    handle_error "Failed to copy certificates for $service_dest."
done

# Clean up old containers and images
echo "Removing all Docker containers..."
docker ps -a -q | xargs -r docker rm -f
handle_error "Failed to remove containers."

echo "Removing all Docker images..."
docker images -q | xargs -r docker rmi -f
handle_error "Failed to remove images."

# Install common dependencies
echo "Installing CommonUtils..."
(cd CommonUtils && mvn clean install)
handle_error "Failed to install CommonUtils."

# Build Maven projects

for service in "${services[@]}"; do
    echo "Building $service..."
    (cd $service && mvn clean package)
    handle_error "Maven build failed for $service."
done

# Check if docker-compose or docker compose is available
compose_cmd=""
if command -v docker-compose &> /dev/null; then
    compose_cmd="docker-compose"
elif command -v docker &> /dev/null; then
    compose_cmd="docker compose"
else
    echo "Neither docker-compose nor docker compose found. Exiting."
    exit 1
fi

# Start services
echo "Starting services with $compose_cmd..."
$compose_cmd up -d
handle_error "Failed to start services."

# Create network if it doesn't exist
network_name="kerberos_storage-kerberosfs-network"
echo "Creating network: $network_name (if not exists)..."
docker network ls | grep -q $network_name || docker network create $network_name
handle_error "Failed to create network: $network_name."

# Connect containers to the network dynamically
services_to_connect=("kerberosfs-auth-service" "kerberosfs-access-control-service" "kerberosfs-storage-service" "kerberosfs-dispatcher-service")

for service in "${services_to_connect[@]}"; do
    container_name=$(docker ps --filter "name=$service" --format "{{.Names}}" | head -n 1)
    if [ -n "$container_name" ]; then
        echo "Connecting $container_name to $network_name..."
        docker network connect $network_name $container_name || true
    else
        echo "Warning: Service $service is not running or was not found."
    fi
done

# Run the client application
echo "Running the client application..."
java -jar KerberosFSClient/target/kerberos-filesystem-client-1.0.0.jar
handle_error "Failed to run the client application."
