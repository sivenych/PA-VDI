FROM alpine:latest
COPY pa-vdi.py /opt/pa-vdi/
ENV PATH /usr/local/bin:$PATH
ENV LANG C.UTF-8
WORKDIR /opt/pa-vdi
RUN apk update && \
        apk add gcc libc-dev libffi-dev python3 python3-dev py3-pip && \
#        pip3 install wheel && \
        pip3 install aiodns && \
        rm -rf DIST Advance *.iml Dockerfile* .git .idea Realization compressed debug* input* *test* *example*
EXPOSE 9000/udp
ENV LOCAL_ADDR 127.0.0.1:9000
ENV REMOTES 127.0.0.1:9999,127.0.0.1:9998
ENTRYPOINT ["python3", "/opt/pa-vdi/pa-vdi.py"]
