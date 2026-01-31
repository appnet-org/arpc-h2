#!/bin/bash

echo "Applying sidecar proxy rules for gRPC (TCP ports 8081-8089)..."

iptables-restore <<'EOF'
*nat
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

### --- EXCLUSIONS (prevent infinite loops & preserve system traffic) ---

# 1. Do NOT intercept proxy's own traffic
-A OUTPUT -m owner --uid-owner 1337 -j RETURN

# 2. Do NOT intercept loopback (prevents hairpin loops)
-A OUTPUT -o lo -j RETURN

# 3. Do NOT intercept DNS (recommended)
-A OUTPUT -p udp --dport 53 -j RETURN
-A OUTPUT -p tcp --dport 53 -j RETURN

# 4. Preserve existing connections
-A PREROUTING -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A OUTPUT     -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN


### --- INBOUND INTERCEPTION (for traffic *into* the app) ---

# Redirect client -> app incoming traffic to inbound proxy at 15006
# NOTE: Exclude port 8080 (frontend) because it serves HTTP/1.1 web traffic
# Only intercept gRPC services on ports 8081-8089:
#   cart: 8081, productcatalog: 8082, currency: 8083, payment: 8084,
#   shipping: 8085, email: 8086, checkout: 8087, recommendation: 8088, ad: 8089
-A PREROUTING -p tcp --dport 8081:8089 -j REDIRECT --to-ports 15006


### --- OUTBOUND INTERCEPTION (for app-initiated connections) ---

# Redirect app outbound traffic -> outbound proxy at 15002
# Intercept gRPC calls to backend services on ports 8081-8089
-A OUTPUT -p tcp --dport 8081:8089 -m owner ! --uid-owner 1337 -j REDIRECT --to-ports 15002

COMMIT
EOF

echo "Sidecar proxy rules applied successfully for gRPC."
