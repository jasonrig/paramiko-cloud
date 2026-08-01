FROM alpine:3.24.1

RUN apk add --no-cache openssh-server \
    && adduser -D -s /bin/sh certuser \
    && echo "certuser:password-authentication-is-disabled" | chpasswd \
    && ssh-keygen -A \
    && mkdir -p /run/sshd

COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22

HEALTHCHECK --interval=1s --timeout=2s --start-period=2s --retries=30 \
    CMD test -s /run/sshd.pid && kill -0 "$(cat /run/sshd.pid)"

CMD ["/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config"]
