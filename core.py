import json
import logging
import pika
import uuid
from scanners.sqli_scanner import scan_sqli
from scanners.xss_scanner import scan_xss
from scanners.headers_scanner import scan_headers
from datetime import datetime

# =========================
# Logging Configuration
# =========================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("PythonScanner")

# =========================
# RabbitMQ Configuration
# =========================
RABBIT_HOST = "localhost"
SCAN_REQUEST_QUEUE = "scan-request"
SCAN_RESULT_QUEUE = "scan-results-queue"

# =========================
# Message Handler
# =========================
def on_message(ch, method, properties, body):
    logger.info("📩 Scan request received")
    payload = json.loads(body.decode("utf-8"))

    # MassTransit wraps actual message under 'message' key
    message = payload.get("message")
    if not message:
        logger.error("❌ Invalid message format: %s", payload)
        return

    scan_id = message.get("scanId")
    url = message.get("url")

    if not scan_id or not url:
        logger.error("❌ Missing scanId or url: %s", message)
        return

    logger.info("🔍 Starting scan | ScanId=%s | Url=%s", scan_id, url)

    vulnerabilities = []
    vulnerabilities += scan_sqli(url)
    vulnerabilities += scan_xss(url)
    vulnerabilities += scan_headers(url)

    # Envelope compatible with MassTransit
    result_message = { 
        "scanId": scan_id,
        "vulnerabilities": vulnerabilities
}
    logger.info("result_message: %s", json.dumps(result_message, indent=2))
   
    ch.basic_publish(
        exchange="",
        routing_key=SCAN_RESULT_QUEUE,
        body=json.dumps(result_message),
        properties=pika.BasicProperties(content_type="application/json")
    )

    logger.info("✅ Scan completed | ScanId=%s | Vulns=%d", scan_id, len(vulnerabilities))

# =========================
# Application Entry Point
# =========================
def start():
    try:
        logger.info("🔌 Connecting to RabbitMQ at %s", RABBIT_HOST)

        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=RABBIT_HOST)
        )
        channel = connection.channel()

        channel.queue_declare(queue=SCAN_REQUEST_QUEUE, durable=True)
        channel.queue_declare(queue=SCAN_RESULT_QUEUE, durable=True)

        channel.basic_consume(
            queue=SCAN_REQUEST_QUEUE,
            on_message_callback=on_message,
            auto_ack=True
        )

        logger.info("🐍 Python Scanner is running and waiting for messages...")
        channel.start_consuming()

    except Exception:
        logger.exception("🔥 Failed to start Python Scanner")

if __name__ == "__main__":
    start()
