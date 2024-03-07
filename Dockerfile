FROM node:latest

WORKDIR /example

COPY package*.json ./

RUN npm install

COPY . .

EXPOSE 3001

CMD [ "node", "ldap.js" ]