from fastapi import APIRouter

from app.api.v1 import auth, cases, connectors, detections, events, health, hosts, ingest, meta, users

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(ingest.router)
api_router.include_router(connectors.router)
api_router.include_router(events.router)
api_router.include_router(hosts.router)
api_router.include_router(detections.router)
api_router.include_router(cases.router)
api_router.include_router(meta.router)
