FROM python:3.13.7-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --requirement requirements.txt && useradd --uid 10001 --create-home hosting
COPY hosting_api ./hosting_api
COPY schema ./schema
USER 10001:10001
EXPOSE 8080
CMD ["python", "-m", "hosting_api"]
