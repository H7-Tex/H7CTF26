# The Ladder portal (public role, no secret). Build context = pwn/aegis.
FROM python:3.12-slim
RUN pip install --no-cache-dir flask==3.0.3
COPY graded/portal/portal.py /portal.py
EXPOSE 8080
CMD ["python", "/portal.py"]
