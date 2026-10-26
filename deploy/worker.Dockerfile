# CyberSafe24 Shield – isolierter Scan-Worker
# Build:  docker build -f deploy/worker.Dockerfile -t cybersafe24-worker .
FROM public.ecr.aws/docker/library/golang:1.26-bookworm AS tools
# Versionen bewusst gepinnt (MIT-lizenziert, ProjectDiscovery)
ARG SUBFINDER_VERSION=v2.17.0
ARG NUCLEI_VERSION=v3.11.1
# Optionales Build-Secret "extra_ca" nur für Umgebungen mit TLS-terminierendem Proxy
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -f /run/secrets/extra_ca ]; then export SSL_CERT_FILE=/run/secrets/extra_ca; fi; \
    CGO_ENABLED=0 go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} \
 && CGO_ENABLED=0 go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}

FROM public.ecr.aws/docker/library/node:22-bookworm-slim AS deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -f /run/secrets/extra_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/extra_ca; fi; \
    pnpm install --frozen-lockfile --prod=false

FROM public.ecr.aws/docker/library/node:22-bookworm-slim
ENV NODE_ENV=production
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tini && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /home/scanner --create-home scanner
COPY --from=tools /go/bin/subfinder /go/bin/nuclei /usr/local/bin/
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json tsconfig.json ./
COPY src/lib ./src/lib
COPY worker ./worker
USER scanner
ENV HOME=/home/scanner SUBFINDER_BIN=/usr/local/bin/subfinder NUCLEI_BIN=/usr/local/bin/nuclei
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node_modules/.bin/tsx", "worker/index.ts"]
