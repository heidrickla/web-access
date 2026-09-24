FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      xrdp xorgxrdp xfce4 xfce4-terminal dbus-x11 mousepad xauth ssl-cert \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash ops \
 && echo "startxfce4" > /home/ops/.xsession \
 && chown ops:ops /home/ops/.xsession \
 && adduser xrdp ssl-cert
COPY entry.sh /entry.sh
RUN chmod +x /entry.sh
EXPOSE 3389
CMD ["/entry.sh"]
