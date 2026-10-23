from threading import Thread
from uuid import UUID

from app.core.config import settings


def enqueue_ingestion(job_id: UUID, organization_id: UUID) -> None:
    runner = settings.job_runner
    if runner == "inline":
        from app.ingestion.service import process_ingestion_job

        process_ingestion_job(job_id, organization_id)
        return
    if runner == "celery":
        from app.workers.tasks import process_ingestion_job_task

        process_ingestion_job_task.delay(str(job_id), str(organization_id))
        return

    from app.ingestion.service import process_ingestion_job

    thread = Thread(
        target=process_ingestion_job,
        args=(str(job_id), organization_id),
        daemon=True,
    )
    thread.start()
