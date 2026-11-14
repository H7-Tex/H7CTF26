FROM python:3.12-slim
RUN useradd -m -u 1000 portal
WORKDIR /tq
COPY graded/portal/portal.py /tq/portal.py
USER portal
EXPOSE 1337
CMD ["python3", "/tq/portal.py"]
