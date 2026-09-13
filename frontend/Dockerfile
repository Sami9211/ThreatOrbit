# Stage 1: build the Node SSR app.
# Base images pinned by digest (supply-chain integrity); Dependabot's docker
# ecosystem bumps both the tag and the digest when a new image ships.
FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
# The dashboard API URL the *browser* will call - baked in at build time.
ARG NEXT_PUBLIC_API_URL=http://localhost:8002
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
RUN npm run build

# Stage 2: run the Node SSR server (`next start`). No nginx - the Next server
# serves the app and applies the security headers from next.config headers().
FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000
ENV HOSTNAME=0.0.0.0
# Production dependencies + the build output + config needed by `next start`.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --from=build /app/.next ./.next
COPY --from=build /app/next.config.mjs ./next.config.mjs
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:3000/',r=>process.exit(r.statusCode<500?0:1)).on('error',()=>process.exit(1))"
CMD ["npx", "--no-install", "next", "start", "-p", "3000"]
