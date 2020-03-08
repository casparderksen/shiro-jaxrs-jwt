#!/bin/sh

RESOURCE=$1
URL=http://localhost:8080/shiro-jaxrs-jwt/api/${RESOURCE:-'ping'}
TOKEN=$(cat src/test/jwtenizr/token.jwt)
echo "> GET ${URL}"
curl -i -H"Authorization: Bearer ${TOKEN}" "${URL}"
