# Production multi-stage Dockerfile for HelloHoney (Frontend + Backend)
FROM node:20-alpine AS build

# Build frontend
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Setup backend
WORKDIR /app
COPY backend/package*.json ./backend/
RUN npm --prefix backend install --omit=dev

COPY backend/ ./backend/
COPY --from=build /app/frontend/dist ./frontend/dist

ENV NODE_ENV=production
ENV PORT=5000

EXPOSE 5000

CMD ["node", "backend/server.js"]
