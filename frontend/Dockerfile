# Stage 1: build the static export.
# Base images pinned by digest (supply-chain integrity); Dependabot's docker
# ecosystem bumps both the tag and the digest when a new image ships.
FROM node:26-alpine@sha256:3ad34ca6292aec4a91d8ddeb9229e29d9c2f689efd0dd242860889ac71842eba AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
# The dashboard API URL the *browser* will call — baked in at build time.
ARG NEXT_PUBLIC_API_URL=http://localhost:8002
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
RUN npm run build

# Stage 2: serve the export with nginx (digest-pinned, as above).
FROM nginx:1.31-alpine@sha256:8b1e78743a03dbb2c95171cc58639fef29abc8816598e27fb910ed2e621e589a
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/out /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -q --spider http://127.0.0.1/ || exit 1
