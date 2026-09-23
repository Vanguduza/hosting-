FROM python:3.13-alpine
RUN adduser -D -u 10001 app
WORKDIR /app
COPY server.py .
USER 10001:10001
EXPOSE 8080
CMD ["python", "server.py"]
