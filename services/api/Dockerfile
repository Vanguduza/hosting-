# syntax=docker/dockerfile:1
FROM python:3.13.7-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./
RUN --mount=type=secret,id=build_ca,required=false \
    if [ -s /run/secrets/build_ca ]; then export PIP_CERT=/run/secrets/build_ca; fi; \
    pip install --no-cache-dir --requirement requirements.txt && useradd --uid 10001 --create-home hosting
COPY --chown=10001:10001 hosting_api ./hosting_api
COPY --chown=10001:10001 schema ./schema
USER 10001:10001
EXPOSE 8080
CMD ["python", "-m", "hosting_api"]
