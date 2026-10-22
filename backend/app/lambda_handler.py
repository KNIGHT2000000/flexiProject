"""
AWS Lambda entry point for PhishGuard Cloud.
Bridges API Gateway HTTP API / REST API events to the FastAPI ASGI application via Mangum.
Automatically strips API Gateway stage prefixes (/prod, /staging) so FastAPI routes resolve cleanly.
"""
from mangum import Mangum
from app.main import app

asgi_handler = Mangum(app, lifespan="off")


def handler(event, context):
    """
    AWS Lambda entry handler.
    Intercepts and strips stage prefixes (e.g. /prod or /staging) from HTTP API v2 and REST events
    before dispatching to FastAPI.
    """
    if isinstance(event, dict):
        stage = event.get("requestContext", {}).get("stage")
        if stage and stage != "$default":
            stage_prefix = f"/{stage}"
            raw_path = event.get("rawPath", "")
            if raw_path.startswith(stage_prefix):
                event["rawPath"] = raw_path[len(stage_prefix):] or "/"

            http_info = event.get("requestContext", {}).get("http", {})
            http_path = http_info.get("path", "")
            if http_path.startswith(stage_prefix):
                http_info["path"] = http_path[len(stage_prefix):] or "/"

            path_v1 = event.get("path", "")
            if path_v1.startswith(stage_prefix):
                event["path"] = path_v1[len(stage_prefix):] or "/"

    return asgi_handler(event, context)
