FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 parallax
WORKDIR /app
COPY pyproject.toml README.md ./
COPY runtime ./runtime
RUN pip install --no-cache-dir '.[runtime]'
USER parallax
EXPOSE 8000
CMD ["uvicorn", "parallax_omega.api:app", "--host", "0.0.0.0", "--port", "8000"]
