# Build from the repository root:
#   docker build -f reproduction/Dockerfile -t waves .
#   docker run --rm waves
FROM python:3.12-slim

WORKDIR /waves
COPY reproduction/requirements.txt reproduction/requirements.txt
RUN pip install --no-cache-dir -r reproduction/requirements.txt

COPY . .
ENV MPLBACKEND=Agg PYTHONIOENCODING=utf-8

CMD ["python", "scripts/reproduce_results.py", "--with-helpers"]
