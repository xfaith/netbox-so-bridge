FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /app/

RUN useradd --create-home --uid 10001 bridge \
    && mkdir -p /data /home/bridge/.ssh \
    && chown -R bridge:bridge /app /data /home/bridge


USER bridge

CMD ["python", "/app/main.py"]
