ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}

WORKDIR /opt/cyberdetect
COPY docker/phase1/proxy_server.py docker/phase1/seed_target.py ./
RUN mkdir -p /telemetry/public /telemetry/oracle /state && \
    chown -R 65534:65534 /telemetry /state
USER 65534:65534
EXPOSE 8081
CMD ["python", "/opt/cyberdetect/proxy_server.py"]
