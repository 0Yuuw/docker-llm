FROM python:3.11-slim

RUN apt update && apt install -y build-essential git cmake curl libopenblas-dev libfftw3-dev && \
    pip install --no-cache-dir llama-cpp-python fastapi uvicorn && \
    apt clean

WORKDIR /app
COPY main.py .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

