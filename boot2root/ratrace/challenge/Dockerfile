FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server sudo iproute2 procps gcc libc6-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- users & groups ---
# guest: the entry account (creds handed to players). mel: the ops engineer. staff: can run netmon.
RUN useradd -m -s /bin/bash guest \
    && useradd -m -s /bin/bash mel \
    && groupadd opsstaff \
    && usermod -aG opsstaff mel \
    && echo 'guest:guest' | chpasswd \
    && echo 'mel:S9x!freight-ops' | chpasswd

# --- stage 1 privesc: guest may run awk AS mel without a password (GTFObins) ---
RUN echo 'guest ALL=(mel) NOPASSWD: /usr/bin/awk' > /etc/sudoers.d/ops \
    && chmod 440 /etc/sudoers.d/ops

# --- stage 2 privesc: SUID-root netmon, runnable only by the opsstaff group ---
COPY netmon.c /tmp/netmon.c
RUN gcc /tmp/netmon.c -o /usr/local/bin/netmon \
    && chown root:opsstaff /usr/local/bin/netmon \
    && chmod 4750 /usr/local/bin/netmon \
    && rm -f /tmp/netmon.c

# a little ops flavor: mel's home has a note pointing at the tooling
RUN printf 'ops runbook:\n- interface/socket checks: run `netmon` (staff only)\n- do NOT sudo for this\n' > /home/mel/RUNBOOK.txt \
    && chown mel:mel /home/mel/RUNBOOK.txt

# --- sshd ---
RUN sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && ssh-keygen -A

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
CMD ["/entrypoint.sh"]
