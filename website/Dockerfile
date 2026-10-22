# HomeProxy website: static build (no npm install) + unprivileged nginx.
# Coolify: Dockerfile build pack, base directory "website/", port 8080.
FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS build

WORKDIR /app
COPY package.json site.json ./
COPY scripts/build.mjs ./scripts/build.mjs
COPY scripts/lib ./scripts/lib
COPY src ./src
ARG SOURCE_COMMIT=unreleased
# production refuses placeholders (donate, license, screenshots); use "preview" for local QA only.
ARG SITE_MODE=production
ENV SOURCE_COMMIT=$SOURCE_COMMIT
RUN if [ "$SITE_MODE" = "production" ]; then node scripts/build.mjs --production; \
    elif [ "$SITE_MODE" = "preview" ]; then node scripts/build.mjs; \
    else echo "SITE_MODE must be production or preview" >&2; exit 1; fi

FROM nginx:1.29-alpine@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de AS runtime
ARG SOURCE_COMMIT=unreleased
LABEL org.opencontainers.image.title="homeproxy-website" \
      org.opencontainers.image.source="https://github.com/thetedotgg/homeproxy" \
      org.opencontainers.image.revision=$SOURCE_COMMIT
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/security-headers.conf /etc/nginx/security-headers.conf
COPY --from=build /app/dist /usr/share/nginx/html
USER nginx
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz | grep -q '"status":"ok"' || exit 1
ENTRYPOINT []
CMD ["nginx", "-g", "daemon off;"]
