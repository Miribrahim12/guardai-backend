# Python-un stabil versiyasını seçirik
FROM python:3.11-slim

# İş sahəsini təyin edirik
WORKDIR /app

# Lazımi sistem paketlərini yükləyirik
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Kitabxanaları kopyalayıb yükləyirik
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Bütün proyekt kodlarını kopyalayırıq
COPY . .

# Serveri işə salırıq
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]