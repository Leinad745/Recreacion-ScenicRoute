FROM python:3.12-slim

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

EXPOSE 8080
# El control plane (9101) NO se expone: escucha solo en 127.0.0.1 dentro del contenedor.
CMD ["python", "app/server.py"]
