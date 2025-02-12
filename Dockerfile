FROM docker.io/library/python:3.13.0-slim-bookworm

RUN useradd --create-home --uid 1000 jovyan

COPY guacamole_handler /opt/guacamole_handler
COPY requirements.txt /src/
RUN pip install --no-cache-dir \
    -r /src/requirements.txt

USER jovyan

EXPOSE 8040
CMD ["python", "/opt/guacamole_handler/guacamole_handler.py"]
