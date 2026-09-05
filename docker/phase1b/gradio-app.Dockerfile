ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}
RUN pip install --no-cache-dir "gradio==4.12.0" "fastapi==0.111.0" "huggingface_hub==0.20.3"
COPY docker/phase1b/app.py /app/app.py
ENV HOME=/tmp GRADIO_TEMP_DIR=/tmp/gradio
WORKDIR /tmp
EXPOSE 7860
CMD ["python", "/app/app.py"]
