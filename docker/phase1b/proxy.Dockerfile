ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}
WORKDIR /opt/cyberdetect
COPY docker/phase1b/proxy_server_pathtrav.py ./proxy_server.py
RUN mkdir -p /telemetry/public /telemetry/oracle /state && chown -R 65534:65534 /telemetry /state
USER 65534:65534
EXPOSE 8081
CMD ["python", "/opt/cyberdetect/proxy_server.py"]
