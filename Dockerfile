FROM node:lts

WORKDIR /browser
COPY package*.json ./
RUN npm install
COPY . .
USER node
EXPOSE 8080
CMD [ "node", "index.js" ]