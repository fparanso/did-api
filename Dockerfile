# Stage 1: Build dependencies and project files
FROM oven/bun:1 AS builder
WORKDIR /app

# Copy dependency configs
COPY package.json bun.lock tsconfig.json ./

# Install dependencies (including devDependencies if needed for running migrations, tests, etc.)
RUN bun install --frozen-lockfile

# Copy local code
COPY . .

# Stage 2: Final runtime container
FROM oven/bun:1-slim
WORKDIR /app

# Copy files from builder
COPY --from=builder /app /app

EXPOSE 3000

ENV NODE_ENV=production
ENV PORT=3000

CMD ["bun", "run", "src/index.ts"]
