"""
AWS Lambda entry point for PhishGuard Cloud.
Bridges API Gateway HTTP API / REST API events to the FastAPI ASGI application via Mangum.
"""
from mangum import Mangum
from app.main import app

# Lifespan off avoids startup/shutdown event hangs in ephemeral Lambda execution
handler = Mangum(app, lifespan="off")
