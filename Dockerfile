FROM node:20-slim
RUN apt-get update -y && apt-get install -y openssl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json schema.prisma ./
RUN npm install --omit=dev && npx prisma generate
COPY server.cjs ./
ENV NODE_ENV=production
CMD ["sh", "-c", "npx prisma db push --skip-generate && node server.cjs"]
