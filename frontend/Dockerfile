FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:24-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app ./
RUN chown -R node:node /app
USER node
EXPOSE 3000
CMD ["npm", "run", "start"]
