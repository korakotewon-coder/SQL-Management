FROM node:20-alpine AS base
WORKDIR /app

# Install deps first (better layer caching)
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev

# Copy app
COPY . .

# Expose port (configurable via APP_PORT, default 3000)
ENV APP_PORT=3000
EXPOSE 3000

# Run
CMD ["node", "index.js"]
