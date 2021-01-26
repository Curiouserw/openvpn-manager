FROM alpine:3.11.5

ENV LANG=en_US.UTF-8 \
    LANGUAGE=en_US.UTF-8 \
    TZ=Asia/Shanghai


RUN sed -i "s/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g" /etc/apk/repositories \
    && apk add --no-cache dumb-init ca-certificates tzdata bash bash-doc bash-completion \
    && wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub \
    && wget -q https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.29-r0/glibc-2.29-r0.apk \
    && wget -q https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.29-r0/glibc-bin-2.29-r0.apk \
    && wget -q https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.29-r0/glibc-i18n-2.29-r0.apk \
    && apk add glibc-2.29-r0.apk glibc-bin-2.29-r0.apk glibc-i18n-2.29-r0.apk \
    && rm -rf /opt/jdk-8u241-linux-x64.tar.gz /usr/lib/jvm glibc-2.29-r0.apk glibc-bin-2.29-r0.apk  glibc-i18n-2.29-r0.apk \
    && /usr/glibc-compat/bin/localedef --force --inputfile POSIX --charmap UTF-8 "$LANG" || true \
    && echo "export LANG=$LANG" > /etc/profile.d/locale.sh \
    && apk del glibc-i18n \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo "Asia/Shanghai" > /etc/timezone

ENTRYPOINT  ["dumb-init", "--","/applications/openvpn-manager"]

COPY target /applications

WORKDIR /applications
