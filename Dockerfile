FROM node:22-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY . .
ENV PORT=8080 NODE_ENV=production
EXPOSE 8080
CMD ["node", "src/server.mjs"]
