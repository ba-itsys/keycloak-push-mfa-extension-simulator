# Keycloak push mfa extension simulator

Simulator for Keycloak push MFA Extension

## Quick Start

### Local Development

```bash
# Start the Spring Boot application
mvn spring-boot:run

# In another terminal, start TypeScript watch mode (optional, for live reloading)
npm run dev
```

The application will be available at `http://localhost:5000/mock`

### Docker

```bash
# Build the Docker image
docker build -t push-mfa-extension-simulator .

# Run the container
docker run -p 5000:5000 push-mfa-extension-simulator

# Open in browser: http://localhost:5000/mock
```

## Toolchain & Build

### Prerequisites

- **Java 21**: For running Spring Boot application
- **Node.js 20.11.1**: Automatically installed and managed by Maven frontend plugin
- **Maven 3.8+**: For building the project

### Build Tools & Workflow

#### TypeScript & Bundling

- **TypeScript 5.0+**: Type-safe JavaScript development
- **ESBuild 0.27.1**: Ultra-fast bundler for ES modules
- **Build output**: `npm run build` compiles TS to `src/main/resources/static/js/`

#### Code Quality

- **ESLint 8.57**: TypeScript linting with `@typescript-eslint` parser
- **Prettier 3.2.5**: Code formatting
- **Commands**:
  - `npm run lint` - Check for issues
  - `npm run lint:fix` - Auto-fix ESLint errors
  - `npm run format` - Format code with Prettier
  - `npm run format:check` - Verify formatting compliance

#### Complete Build Workflow

```bash
# Development: watch mode TypeScript compilation
npm run dev

# Production build
npm run build

# Linting & formatting
npm run lint:fix
npm run format

# Maven build (includes TypeScript build)
mvn clean package

# Run tests & checks (after AGENTS.md workflow)
mvn spotless:apply
mvn verify
```

## Architecture & CORS

### The Problem: Frontend + Backend on Same Host

When running the simulator mock and Keycloak on the same host, you encounter **CORS (Cross-Origin Resource Sharing)** restrictions:

1. **Keycloak** typically runs on port `8080` (e.g., `http://localhost:8080/realms/demo`)
2. **Mock simulator** runs on port `5000` (e.g., `http://localhost:5000/mock`)
3. **Different ports = different origins** → CORS blocks frontend requests

#### CORS Error Example

```
Access to XMLHttpRequest at 'http://localhost:8080/realms/demo/...'
from origin 'http://localhost:5000' has been blocked by CORS policy
```

### Solution: Reverse Proxy with Nginx

Use an **nginx reverse proxy** to serve both Keycloak and the mock simulator under the **same host** and **same port** (443/HTTPS), eliminating CORS issues.

#### Architecture

```
Client (Browser)
    ↓
https://myapp.local (nginx on port 443)
    ├→ /mock → http://host.docker.internal:5000/mock (mock simulator)
    └→ /realms → http://host.docker.internal:8080 (Keycloak)
```

All requests come from the same origin (`https://myapp.local`), so CORS is not triggered.

## Reverse Proxy Setup with Nginx

### Prerequisites

1. **SSL Certificates**: You need valid certificates for `myapp.local`

   ```bash
   # Example: Create a self-signed cert (for testing only)
   mkdir -p /mnt/c/certs/myapp
   cd /mnt/c/certs/myapp
   openssl req -x509 -newkey rsa:4096 -keyout myapp.local-key.pem -out myapp.local.pem -days 365 -nodes
   ```

2. **Hosts file entry**: Add `myapp.local` to your hosts file

   ```
   127.0.0.1 myapp.local
   ```

3. **Docker network**: Ensure docker can reach your host services

### Running the Nginx Proxy

```bash
# Stop and remove any existing container
docker rm -f myapp-local-nginx 2>/dev/null || true

# Start nginx with the provided config
docker run --name myapp-local-nginx \
  -p 80:80 -p 443:443 \
  --add-host=host.docker.internal:host-gateway \
  -v "$(pwd)/nginx.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "/mnt/c/certs/myapp:/etc/nginx/certs:ro" \
  nginx:alpine
```

### Key Proxy Features (nginx.conf)

#### HTTP to HTTPS Redirect

```nginx
# Port 80 → 443 (HTTP to HTTPS)
server {
  listen 80;
  server_name myapp.local;
  return 301 https://$host$request_uri;
}
```

#### Mock Simulator Proxy

```nginx
location /mock {
  proxy_pass http://host.docker.internal:5000/mock/;
  proxy_http_version 1.1;

  # Forward client headers for proper request context
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header X-Forwarded-Prefix /mock;
}

# Handle /mock without trailing slash
location = /mock {
  return 301 /mock/;
}
```

#### Keycloak Proxy

```nginx
location / {
  proxy_pass http://host.docker.internal:8080;
  proxy_http_version 1.1;

  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-Proto https;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Host $host;
  proxy_set_header X-Forwarded-Port 443;
}
```

### Complete Local Setup (Docker Compose Alternative)

```bash
# 1. Start Keycloak
docker run --name keycloak \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  keycloak:latest start-dev

# 2. Start mock simulator
mvn spring-boot:run  # or docker run the image

# 3. Start nginx proxy
docker run --name myapp-local-nginx \
  -p 80:80 -p 443:443 \
  --add-host=host.docker.internal:host-gateway \
  -v "$(pwd)/nginx.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "/mnt/c/certs/myapp:/etc/nginx/certs:ro" \
  nginx:alpine

# 4. Access via: https://myapp.local
```

### Testing the Proxy Configuration

```bash
# Test mock endpoint
curl -k https://myapp.local/mock

# Test Keycloak endpoint
curl -k https://myapp.local/realms/demo

# Check headers are properly forwarded
curl -k -v https://myapp.local/mock/info
```

### Common Issues & Solutions

| Issue                       | Cause                         | Solution                                              |
| --------------------------- | ----------------------------- | ----------------------------------------------------- |
| SSL certificate error       | Self-signed or untrusted cert | Add `-k` to curl, accept in browser                   |
| `myapp.local` not resolving | Hosts file not updated        | Add `127.0.0.1 myapp.local` to `/etc/hosts`           |
| Cannot reach host services  | Docker networking issue       | Verify `--add-host=host.docker.internal:host-gateway` |
| 502 Bad Gateway             | Backend service not running   | Start Keycloak and mock simulator                     |
| CORS still occurring        | Proxy not properly configured | Check `X-Forwarded-*` headers are present             |

## Configuration

### Application Settings

Edit `src/main/resources/application.yaml`:

```yaml
server:
  port: 5000
  address: 0.0.0.0
  servlet:
    context-path: /mock

app:
  env: 'dev'
```

### Demo Realm

The example realm JSON configuration is located at `config/demo-realm.json` and defines the realm `demo`.

Helper scripts and documentation should reference `/realms/demo/...` endpoints.

## Project Structure

```
src/main/resources/
├── static/
│   ├── js/          # Compiled JavaScript bundles
│   ├── ts/          # TypeScript source files
│   │   ├── pages/   # Page-specific logic (enroll, confirm, info)
│   │   └── util/    # Shared utilities (crypto, HTTP, tokens)
│   └── keys/        # JWK keys for crypto operations
├── views/           # Thymeleaf HTML templates
└── application.yaml # Spring Boot configuration
```

## Device-Facing Endpoints

Device endpoints are located under `/realms/<realm>/push-mfa/...` and expect **DPoP-bound tokens** (Demonstration of Proof-of-Possession).

Keep samples and tests aligned with the current realm name and URL structure.
