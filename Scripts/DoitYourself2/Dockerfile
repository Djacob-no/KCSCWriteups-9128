from python:3.12-slim@sha256:abc799c7ee22b0d66f46c367643088a35e048bbabd81212d73c2323aed38c64f

RUN apt-get update && \
    apt-get install -y socat

WORKDIR /opt
COPY chall.py flag.txt ./

EXPOSE 1337

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:'python3 ./chall.py',pty,raw,echo=0,stderr,setsid,sigint"]