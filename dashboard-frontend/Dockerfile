FROM node:20-alpine
WORKDIR /app

# Install dependencies first for better layer caching
COPY package*.json ./
RUN npm install --legacy-peer-deps

# Copy source and produce an optimized production build.
# NEXT_PUBLIC_* values are inlined at build time, so they must be present here.
COPY . .
ARG NEXT_PUBLIC_API_URL=""
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
RUN npm run build

EXPOSE 3000
# Serve the compiled build (NOT the dev server)
CMD ["npm", "run", "start"]
