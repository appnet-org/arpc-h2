# Symphony Proxy H2 Init Container for gRPC

This init container sets up iptables rules to intercept TCP traffic for **OnlineBoutique gRPC services** (ports 8080-8089).

## Port Mappings

| Service         | Port |
|-----------------|------|
| frontend        | 8080 |
| cart            | 8081 |
| productcatalog  | 8082 |
| currency        | 8083 |
| payment         | 8084 |
| shipping        | 8085 |
| email           | 8086 |
| checkout        | 8087 |
| recommendation  | 8088 |
| ad              | 8089 |

## How it works

The iptables rules redirect:
- **Inbound traffic** (ports 8081-8089) → proxy port **15006**
- **Outbound traffic** (ports 8081-8089) → proxy port **15002**

**Note:** Port 8080 (frontend) is excluded because it serves HTTP/1.1 web traffic, not gRPC.
The proxy only handles HTTP/2 (gRPC) connections.

The proxy (UID 1337) is excluded from interception to prevent infinite loops.

## Build and Push

```bash
./build_images.sh
```

This will build and push: `appnetorg/symphony-proxy-h2-init-container-grpc:latest`

## Usage in Kubernetes

Update your deployment yaml to use this init container:

```yaml
initContainers:
- name: set-iptables
  image: appnetorg/symphony-proxy-h2-init-container-grpc:latest
  command:
  - /bin/sh
  - -c
  - bash /apply_symphony_iptables.sh
  securityContext:
    runAsUser: 0
    capabilities:
      add:
      - NET_ADMIN
```

## Difference from original init_container

| Version | Target Ports | Protocol | Use Case |
|---------|--------------|----------|----------|
| `init_container` | 11000-11100 | TCP | ARPC applications |
| `init_container_grpc` | 8080-8089 | TCP | gRPC/OnlineBoutique |
