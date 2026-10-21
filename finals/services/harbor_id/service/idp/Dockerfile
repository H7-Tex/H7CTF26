FROM node:24-slim

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src/ ./src/

RUN useradd -r -s /bin/false appuser && mkdir -p /data && chown appuser /data
USER appuser

EXPOSE 7001
CMD ["node", "--experimental-strip-types", "src/index.ts"]
