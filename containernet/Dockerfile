FROM ubuntu:22.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    iproute2 iputils-ping net-tools python3 && rm -rf /var/lib/apt/lists/*
RUN echo "set enable-bracketed-paste off" >> /etc/inputrc
COPY svc.py probe.py /opt/
CMD ["/bin/bash"]
