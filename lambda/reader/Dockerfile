# syntax=docker/dockerfile:1

# ---- Build stage: install deps and bundle the TypeScript handler ----
FROM public.ecr.aws/docker/library/node:22-slim AS build
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run bundle

# ---- Runtime stage: AWS's Lambda Node.js base image ----
# Only the bundled JS crosses into the final image.
FROM public.ecr.aws/lambda/nodejs:24
COPY --from=build /build/dist/index.js ${LAMBDA_TASK_ROOT}/index.js
CMD ["index.handler"]
