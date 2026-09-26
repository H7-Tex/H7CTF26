FROM gcc:13 AS build
WORKDIR /src
COPY challenge/vmrun.c .
RUN gcc -O2 -static -s -o vmrun vmrun.c

FROM python:3.12-slim
RUN pip install --no-cache-dir flask gunicorn pynacl cryptography
WORKDIR /opt/kintsugi
COPY challenge/gen.py challenge/vmisa.py challenge/shardfmt.py challenge/verifier.py ./
COPY handout/README.md ./README.md
COPY --from=build /src/vmrun ./vmrun
COPY challenge/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV FLAG=H7CTF{placeholder}
ENV TEAM_ID=team-local
EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
