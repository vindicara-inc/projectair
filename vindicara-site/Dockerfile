# Vindicara site + Flightdeck console as a server-rendered Node app (adapter-node).
# Double-duty image: vindicara.io's own SSR deploy (ECS Fargate behind ALB) AND
# the self-hostable Flightdeck console artifact a customer runs in their own
# VPC / cloud / air-gapped network. Public routes SSR; Flightdeck runs dynamic.
#
# Run: docker run -p 3000:3000 <image>   (listens on $PORT, default 3000)

# --- build stage: install all deps, build the SvelteKit node server ----------
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

# --- run stage: production deps only + the build output ----------------------
FROM node:22-alpine AS run
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/build ./build
# Vite 8 + adapter-node 5.5.5 bundle the request handler under
# build/server/chunks/, so its import.meta.url-derived asset directory resolves
# to build/server/chunks/client instead of build/client. That makes sirv's
# existsSync check fail, silently dropping static-asset serving so every
# /_app/* request (and favicon) falls through to SSR and 404s, rendering the
# site unstyled. Point client + prerendered at where the handler looks for them.
# Proper fix: align the Vite / adapter-node versions; this symlink is the
# durable workaround until then.
RUN ln -sfn ../../client build/server/chunks/client \
 && ln -sfn ../../prerendered build/server/chunks/prerendered
EXPOSE 3000
# Least privilege: run as the built-in non-root node user.
USER node
# Lightweight liveness for the ALB target group health check.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "build/index.js"]
