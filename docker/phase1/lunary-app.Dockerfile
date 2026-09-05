ARG NODE_IMAGE
FROM ${NODE_IMAGE}

WORKDIR /app
COPY .phase1-source/lunary/ ./
COPY docker/phase1/lunary-package-lock.json ./package-lock.json
RUN npm ci

ENV NODE_ENV=development
EXPOSE 3333
CMD ["npm", "run", "backend:start"]
