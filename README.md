# Running Script to build and run servers

## Prerequisites

Ensure that you have Docker and Docker Compose installed on your system. If not, you can download and install them from the official Docker website:

- [Docker Installation Guide](https://docs.docker.com/get-docker/)
- [Docker Compose Installation Guide](https://docs.docker.com/compose/install/)

## Running the Application with Docker Compose

To run the application using Docker Compose with the `-d` (detached) option, follow these steps:

1. **Clone the Repository:**
    ```bash
    git clone 
    cd 
    ```

2. **Review the `docker-compose.yml` File:**
   Open the `docker-compose.yml` file in a text editor to review the services, configurations, and any environment variables specified.

3. **Build and Run Servers:**
   Execute the following command to execute the script that builds the servers and execute the dockerc-compose.yml file that creates the containers for the servers.
    ```bash
    /bin/bash build_and_run.sh
    ```


## Pre installed users

username: client, password:12345, permissions:rw
username: alice, password:12345, permissions:r

## Some commands to exemplifie

login client 12345
put client /ola.txt (you need to click on the button and submit a file)
get client /ola.txt
get client ola.txt
mkdir client /pasta
mkdir client pasta/
ls client
file client ola.txt# KerberosFS
