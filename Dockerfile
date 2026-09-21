FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev 2>/dev/null || npm install --omit=dev
COPY . .
ENV NODE_ENV=production
EXPOSE 3000
CMD ["sh", "-c", "node serve.js"]
