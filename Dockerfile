FROM node:24-alpine

WORKDIR /app

COPY package.json ./
COPY os/ ./os/
COPY ui/ ./ui/
COPY sdk/ ./sdk/
COPY packages/ ./packages/
COPY src/ ./src/
COPY public/ ./public/
COPY workflows/ ./workflows/

RUN mkdir -p /app/data

ENV PORT=3777 \
    HOST=0.0.0.0 \
    OMNIOS_DATA_DIR=/app/data \
    OMNIOS_LITE=0

EXPOSE 3777

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 3777) + '/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "os/server/http-server.mjs"]
