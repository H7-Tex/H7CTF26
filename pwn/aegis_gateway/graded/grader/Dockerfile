# The Ladder grader (internal role, holds GRADER_SECRET; egress to Anvil). Build context = pwn/aegis_gateway.
FROM python:3.12-slim
RUN pip install --no-cache-dir flask==3.0.3
WORKDIR /app
COPY graded/grader/tokens.py graded/grader/report.py graded/grader/grade.py /app/
CMD ["python", "grade.py"]
