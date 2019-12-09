FROM node:lts-slim

WORKDIR /browser
COPY package*.json ./
RUN npm ci --only=production
COPY . .
USER node
EXPOSE 8080
CMD [ "node", "index.js" ]
