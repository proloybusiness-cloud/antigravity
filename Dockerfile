FROM node:24-alpine

WORKDIR /app

# Zero external dependencies — copy source, UI, and GitOps workflows directly
COPY package.json ./
COPY src ./src
COPY public ./public
COPY workflows ./workflows

# Persistent Hostinger Core Memory & local Drive fallback volume
RUN mkdir -p /app/data

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3777
ENV DATA_DIR=/app/data

EXPOSE 3777

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3777/api/health || exit 1

CMD ["node", "src/server.mjs"]
