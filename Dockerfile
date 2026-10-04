# Multi-stage build: compile TypeScript, then ship only production deps + dist.
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig*.json ./
COPY src ./src
RUN npm run build

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
COPY public ./public
COPY policies ./policies
USER node
EXPOSE 4000
# Set ADMIN_API_KEY and PUBLIC_DASHBOARD=false for any real deployment.
CMD ["node", "dist/index.js"]
