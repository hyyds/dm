FROM node:lts-alpine3.16

LABEL AUTHOR="hyyds" \
      TAG=V1 \
      VERSION=1.0.0

ENV REPO_URL=https://github.com/hyyds/dm.git \
    REPO_BRANCH=main

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true


RUN set -ex \
    && echo -e 'http://dl-cdn.alpinelinux.org/alpine/edge/main/\nhttp://dl-cdn.alpinelinux.org/alpine/edge/community' > /etc/apk/repositories \
    && apk update \
    && apk upgrade \
    && apk add --no-cache bash chromium tzdata git moreutils curl jq openssh-client \
    && rm -rf /var/cache/apk/* \
    && ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo "Asia/Shanghai" > /etc/timezone \
    && npm install pm2  -g \
    && git clone -b $REPO_BRANCH $REPO_URL /dm \
    && cd /dm \
    && npm install \
    && cp /dm/docker/docker_entrypoint.sh /usr/local/bin \
    && chmod +x /usr/local/bin/docker_entrypoint.sh

WORKDIR /dm

ENTRYPOINT ["docker_entrypoint.sh"]


