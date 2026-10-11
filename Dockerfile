FROM node:24-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY --chown=node:node . .
RUN mkdir -p /data/log_archive && chown -R node:node /data
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    LOG_FILE=/data/flashman_logs.json \
    AUDIT_FILE=/data/flashman_audit.jsonl \
    LOG_ARCHIVE_DIR=/data/log_archive
EXPOSE 3000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD node -e "fetch('http://127.0.0.1:3000/health',{signal:AbortSignal.timeout(4000)}).then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
USER node
CMD ["node", "serve.js"]
