from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

celery_app = Celery(
    "sentinelai",
    broker=settings.redis_url or "redis://127.0.0.1:6379/0",
    backend=settings.redis_url or "redis://127.0.0.1:6379/0",
    include=["app.workers.tasks"],
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_acks_late=True,
    task_default_retry_delay=10,
    task_annotations={"app.workers.tasks.process_ingestion_job_task": {"max_retries": 3}},
    beat_schedule={
        "daily-expired-event-cleanup": {
            "task": "app.workers.tasks.cleanup_expired_events_task",
            "schedule": crontab(hour=2, minute=15),
            "options": {"queue": "celery"},
        },
        "poll-cloud-connectors": {
            "task": "app.workers.tasks.poll_due_cloud_connectors_task",
            "schedule": crontab(minute="*/5"),
            "options": {"queue": "celery"},
        },
        "check-system-health": {
            "task": "app.workers.tasks.check_system_health_task",
            "schedule": crontab(minute="*/5"),
            "options": {"queue": "celery"},
        },
        "deliver-alert-notifications": {
            "task": "app.workers.tasks.deliver_notifications_task",
            "schedule": 30.0,
            "options": {"queue": "celery", "expires": 25},
        },
    },
)
