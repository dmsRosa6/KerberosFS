# KerberosFS - Learning Project for Secure File Storage

Kerberos File Storage(KerberosFS) is a learning project aimed at understanding secure file storage systems using the Kerberos authentication protocol. The system consists of multiple components using a microservices architecture and working together to ensure authentication and controlled access to stored files.

## Architecture Overview

KerberosFS is composed of five main components:

1. **Dispatcher (Proxy)** - Acts as an intermediary between the client and the other services, ensuring secure communication.
2. **Authentication Service** - Handles user authentication and issues the necessary Kerberos credentials.
3. **Access Control Service** - Manages permissions and access rights to files.
4. **Storage Service** - The actual storage backend where files are managed.
5. **Client** - The user-facing component that interacts with the dispatcher to execute commands.

## Security Mechanisms

KerberosFS employs multiple layers of security to ensure data integrity and confidentiality:

- **TLS 1.2 Encryption**: 
  - The client communicates with the dispatcher over a TLS 1.2-encrypted socket, where the dispatcher authenticates itself to the client.
  - Mutual TLS 1.2 authentication is enforced between the dispatcher and all backend services (Authentication Service, Access Control Service, and Storage Service).
- **Kerberos Authentication Flow**:
  - The client must authenticate with the Authentication Service.
  - Upon successful authentication, the client requests a Ticket Granting Ticket (TGT).
  - The TGT is then used to obtain a Service Granting Ticket (SGT) for accessing specific services.
- **Diffie-Hellman Key Exchange**:
  - A Diffie-Hellman key exchange is used during authentication to establish a secure session without relying on password-based encryption.
- **Docker Containers**_
  - Provides isolation.

## Command-Line Interface (CLI)

KerberosFS provides a Linux-like command-line interface where users can interact with the storage system after authentication.

### Available Commands

| Command | Arguments | Description |
|---------|-----------|-------------|
| `HELP`  | `()`      | Displays available commands. |
| `LOGIN` | `(username, password)` | Authenticates the user. Must be run before accessing files. |
| `LS`    | `(username, path)` | Lists files and directories in the specified path. |
| `MKDIR` | `(username, path)` | Creates a new directory at the specified path. |
| `PUT`   | `(username, file_path, destination)` | Uploads a file to the storage service. |
| `RM`    | `(username, path)` | Deletes a file or directory at the specified path. |
| `FILE`  | `(username, path)` | Retrieves metadata about a specific file. |
| `CP`    | `(username, source_path, destination_path)` | Copies a file or directory. |
| `GET`   | `(username, path)` | Downloads a file from the storage service. |

## Deployment

KerberosFS runs inside Docker containers to ensure isolation and reproducibility. To deploy the system:

1. **Clone the repository:**
   ```sh
   git clone https://github.com/your-repo/kerberosfs.git
   cd kerberosfs
2. **Setup Certificates (if needed):**   
Run the ```sh ./setup_certificates.sh``` script to configure the necessary certificates. This step also ensures that the passwords are updated as required.
3. **Install Users (Optional):**
Install users(optional), both in te auth and access controll, this is done manually by running the install classses.
4. **Build and Run:**
Execute the ```sh build_and_run.sh``` script to build the Docker images and start the containers.