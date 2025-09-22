# Thesis Experiment — Reproducible Container Vulnerability Scans (Clair + Trivy)

## Structure
```
clair/
  config.yaml
  docker-compose.yml
certs/
  (generated) ca.crt, ca.key, tls.crt, tls.key, ca-bundle.crt, san.cnf
scripts/
  import_all.sh
  scan_trivy.sh
  scan_clair.sh
  aggregate.py
tars/
subjects.yaml
.env
reports/
out/
```

## Prerequisites (run in WSL Ubuntu)
- Docker Desktop with **WSL integration** enabled for this distro
- `curl`, `openssl`, `python3`
- `clairctl` in PATH (build or download)
- (optional) `skopeo`

### Install `clairctl` (Go 1.22)
```bash
sudo snap install go --channel=1.22/stable --classic
GOBIN=$HOME/bin go install github.com/quay/clair/v4/cmd/clairctl@v4.8.0
echo 'export PATH=$HOME/bin:$PATH' >> ~/.bashrc && source ~/.bashrc
clairctl version
```

## Clone
```bash
git clone <your repo url>
cd Thesis_Experiment
```

## TLS for local registry (one-time)
Create `certs/san.cnf`:
```ini
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = v3_req
distinguished_name = dn

[ dn ]
C  = SE
ST = -
L  = -
O  = ThesisLab
CN = registry

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
DNS.2 = host.docker.internal
DNS.3 = registry
IP.1  = 127.0.0.1
```

Generate CA + server certs:
```bash
mkdir -p certs

# CA
openssl genrsa -out certs/ca.key 4096
openssl req -x509 -new -nodes -key certs/ca.key -sha256 -days 3650 \
  -subj "/C=SE/ST=-/L=-/O=ThesisLab/CN=ThesisLab-Local-CA" \
  -out certs/ca.crt

# Server key + CSR
openssl genrsa -out certs/tls.key 4096
openssl req -new -key certs/tls.key -out certs/tls.csr -config certs/san.cnf

# Sign CSR
openssl x509 -req -in certs/tls.csr -CA certs/ca.crt -CAkey certs/ca.key \
  -CAcreateserial -out certs/tls.crt -days 825 -sha256 \
  -extensions v3_req -extfile certs/san.cnf
```

Trust CA for Docker Desktop (WSL):
```bash
sudo mkdir -p /mnt/wsl/docker-desktop/certs.d/localhost:5001 \
             /mnt/wsl/docker-desktop/certs.d/host.docker.internal:5001
sudo cp certs/ca.crt /mnt/wsl/docker-desktop/certs.d/localhost:5001/ca.crt
sudo cp certs/ca.crt /mnt/wsl/docker-desktop/certs.d/host.docker.internal:5001/ca.crt
sudo chmod 644 /mnt/wsl/docker-desktop/certs.d/*:5001/ca.crt
```

Bundle CA for `clairctl`:
```bash
cat /etc/ssl/certs/ca-certificates.crt certs/ca.crt > certs/ca-bundle.crt
```

## Configure `.env`
```dotenv
PUSH_REGISTRY=localhost:5001
PULL_REGISTRY_FOR_CLAIR=host.docker.internal:5001
```

## Start services
```bash
docker compose -f clair/docker-compose.yml up -d
```

## Verify
```bash
curl --cacert certs/ca.crt https://localhost:5001/v2/
curl -fsS http://localhost:6061/metrics >/dev/null && echo "Clair OK"
```

## Import images (from `./tars/*.tar`)
```bash
./scripts/import_all.sh
```

## subjects.yaml (example)
```yaml
subjects:
  - docker.io/library/nginx:1.27
  - quay.io/projectquay/clair:4.8.0
  - localhost:5001/your/repo:tag@sha256:...
```

## Scan — Trivy
```bash
./scripts/scan_trivy.sh subjects.yaml
# outputs: reports/trivy/*.json
```

## Scan — Clair
```bash
export SSL_CERT_FILE="$(pwd)/certs/ca-bundle.crt"
./scripts/scan_clair.sh subjects.yaml
# outputs: reports/clair/*.json
```

## Aggregate
```bash
python3 scripts/aggregate.py reports out/metrics.csv
# outputs: out/metrics.csv
```

## Clean & re-run
```bash
rm -rf reports out && mkdir -p reports/trivy reports/clair out
docker compose -f clair/docker-compose.yml up -d
./scripts/import_all.sh
./scripts/scan_trivy.sh subjects.yaml
export SSL_CERT_FILE="$(pwd)/certs/ca-bundle.crt"
./scripts/scan_clair.sh subjects.yaml
python3 scripts/aggregate.py reports out/metrics.csv
```

## Troubleshooting
- `x509: certificate signed by unknown authority` → ensure CA files exist in `/mnt/wsl/docker-desktop/certs.d/{localhost:5001,host.docker.internal:5001}/ca.crt` and rebuild `certs/ca-bundle.crt`
- `clairctl: command not found` → install with Go 1.22 (see above)
- Clair cannot pull `localhost:5001/...` → scripts rewrite to `host.docker.internal:5001` for in-container access
- Aggregator JSON errors → delete `reports/*` and re-scan
