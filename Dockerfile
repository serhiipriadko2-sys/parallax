FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 parallax
WORKDIR /app
COPY constraints/runtime-dev.lock ./constraints/runtime-dev.lock
RUN python -m pip install --no-cache-dir --require-hashes -r constraints/runtime-dev.lock
COPY pyproject.toml README.md LICENSE ./
COPY runtime ./runtime
RUN python -m pip install --no-cache-dir --no-deps .
USER parallax
EXPOSE 8000
CMD ["uvicorn", "parallax_omega.api:app", "--host", "0.0.0.0", "--port", "8000"]
