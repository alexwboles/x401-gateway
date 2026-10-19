# x401-gateway demo: self-hosted identity wallet + demo merchant.
# Serves the wallet on 8071 and the merchant on 8072, then prints the
# command to run the agent manually (the human approval step stays manual).
FROM python:3.12-slim

RUN pip install --no-cache-dir "cryptography>=41"

WORKDIR /app
COPY . /app

EXPOSE 8071 8072

CMD ["python3", "-m", "demo.run_demo", "--serve-only", \
     "--wallet-port", "8071", "--merchant-port", "8072"]
