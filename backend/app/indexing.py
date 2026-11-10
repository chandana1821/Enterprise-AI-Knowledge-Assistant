"""Persistent PostgreSQL-backed indexing queue and bounded worker."""
import asyncio
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .config import settings
from .connectors import UploadConnector
from .db import SessionLocal
from .models import AuditLog, Document, DocumentChunk, Freshness, IndexingJob, Ingestion
from .rag import (AIProviderError, CHUNK_OVERLAP, CHUNK_SIZE, EMBEDDING_DIMENSIONS,
                  EMBEDDING_SPACE_FINGERPRINT, INDEXING_PIPELINE_VERSION, embed, split_chunks)

log = logging.getLogger(__name__)
MAX_ATTEMPTS = 4  # initial attempt plus three bounded automatic retries
RETRY_DELAYS = (30, 120, 300)
LEASE_SECONDS = 180
SCAN_SECONDS = 30
POLL_SECONDS = 1

def _safe_indexing_error(exc: Exception) -> str:
    if isinstance(exc, AIProviderError):
        if exc.status_code == 429:
            return "Gemini quota reached. The document will retry automatically."
        suffix = f" (HTTP {exc.status_code})" if exc.status_code else ". Check provider configuration and service status."
        return f"{exc.provider} embedding request failed{suffix}"
    if isinstance(exc, FileNotFoundError):
        return "The stored document file is unavailable. Upload the document again."
    if isinstance(exc, ValueError) and "no readable text" in str(exc).lower():
        return "No extractable text was found in this document."
    if isinstance(exc, ValueError) and "embedding" in str(exc).lower():
        return "The embedding provider returned invalid vector data."
    if isinstance(exc, TimeoutError) or "timeout" in type(exc).__name__.lower():
        return "The embedding service timed out. The job will retry automatically."
    return f"Document indexing failed ({type(exc).__name__}). Check the API logs for details."


def indexing_fingerprint(content_hash: str) -> str:
    """Fingerprint every setting that changes the generated vector snapshot."""
    value = "|".join((content_hash, EMBEDDING_SPACE_FINGERPRINT,
                      str(EMBEDDING_DIMENSIONS), str(CHUNK_SIZE), str(CHUNK_OVERLAP),
                      INDEXING_PIPELINE_VERSION))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


async def enqueue_document(db, document: Document, *, old_storage_path: str | None = None,
                           supersedes_document_id=None, force: bool = False) -> IndexingJob:
    """Idempotently enqueue the current document version/hash."""
    now = datetime.now(timezone.utc)
    fingerprint = indexing_fingerprint(document.content_hash)
    values = dict(id=uuid4(), document_id=document.id, workspace_id=document.workspace_id,
                  target_version=document.version, target_hash=document.content_hash,
                  target_fingerprint=fingerprint,
                  status="QUEUED", attempts=0, progress=0, available_at=now,
                  old_storage_path=old_storage_path,
                  supersedes_document_id=supersedes_document_id)
    insert = pg_insert(IndexingJob).values(**values).on_conflict_do_nothing(
        constraint="uq_index_job_document_hash")
    await db.execute(insert)
    job = await db.scalar(select(IndexingJob).where(
        IndexingJob.document_id == document.id,
        IndexingJob.target_hash == document.content_hash).with_for_update())
    if job is None:
        raise RuntimeError("Could not create indexing job")
    if (job.status in {"SUCCEEDED", "SUPERSEDED"} or
        (job.status == "FAILED" and (force or job.target_fingerprint != fingerprint)) or
        (job.status == "QUEUED" and job.target_fingerprint != fingerprint)):
        job.status = "QUEUED"; job.attempts = 0; job.retry_count = 0; job.provider_error_type = None; job.progress = 0
        job.target_version = document.version; job.target_hash = document.content_hash
        job.target_fingerprint = fingerprint
        job.available_at = now; job.locked_until = None; job.last_error = None
        job.finished_at = None; job.started_at = None; job.last_error = None
    if job.status in {"QUEUED", "PROCESSING", "RETRYING"}:
        if old_storage_path and not job.old_storage_path:
            job.old_storage_path = old_storage_path
        if supersedes_document_id:
            job.supersedes_document_id = supersedes_document_id
    elif job.status == "FAILED":
        document.freshness_status = Freshness.FAILED
        document.ingestion_status = Ingestion.FAILED
        document.indexing_error = job.last_error or document.indexing_error
    if job.status in {"QUEUED", "PROCESSING", "RETRYING"}:
        document.freshness_status = Freshness(job.status)
        document.indexing_error = job.last_error if job.status == "RETRYING" else None
        document.indexing_failed_at = None
        document.indexing_progress = job.progress if job.status == "PROCESSING" else 0
        document.ingestion_status = Ingestion.PENDING
    return job


def _read_and_extract(path: str):
    """Run synchronous file parsing off the event loop."""
    import asyncio
    return asyncio.run(UploadConnector().fetch(path))


async def _set_progress(job_id, document_id, version, progress: int):
    async with SessionLocal() as db:
        await db.execute(update(IndexingJob).where(IndexingJob.id == job_id,
            IndexingJob.status == "PROCESSING").values(progress=progress,
            locked_until=datetime.now(timezone.utc) + timedelta(seconds=LEASE_SECONDS)))
        await db.execute(update(Document).where(Document.id == document_id,
            Document.version == version, Document.freshness_status != Freshness.DELETED)
            .values(indexing_progress=progress))
        await db.commit()


async def _heartbeat(job_id):
    while True:
        await asyncio.sleep(30)
        async with SessionLocal() as db:
            await db.execute(update(IndexingJob).where(IndexingJob.id == job_id,
                IndexingJob.status == "PROCESSING").values(
                    locked_until=datetime.now(timezone.utc) + timedelta(seconds=LEASE_SECONDS)))
            await db.commit()


async def _mark_superseded(job_id, document_id, target_version, target_hash, actual_hash=None,
                           file_stat=None):
    async with SessionLocal() as db:
        job = await db.get(IndexingJob, job_id)
        doc = await db.scalar(select(Document).where(Document.id == document_id).with_for_update())
        if not job:
            return
        job.status = "SUPERSEDED"; job.progress = 0; job.locked_until = None
        job.finished_at = datetime.now(timezone.utc)
        if doc and doc.freshness_status != Freshness.DELETED:
            if actual_hash and doc.version == target_version and doc.content_hash == target_hash:
                doc.content_hash = actual_hash
                doc.version += 1
                doc.freshness_status = Freshness.STALE
                if file_stat:
                    doc.storage_mtime_ns = file_stat.st_mtime_ns
                    doc.storage_size = file_stat.st_size
                    doc.source_last_modified_at = datetime.fromtimestamp(file_stat.st_mtime, timezone.utc)
            await enqueue_document(db, doc)
        await db.commit()


async def _fail_job(job_id, document_id, target_version, target_hash, error: str, exc: Exception | None = None):
    now = datetime.now(timezone.utc)
    async with SessionLocal() as db:
        job = await db.get(IndexingJob, job_id)
        doc = await db.scalar(select(Document).where(Document.id == document_id).with_for_update())
        if not job:
            return
        current_fingerprint = indexing_fingerprint(doc.content_hash) if doc else None
        if doc and doc.freshness_status != Freshness.DELETED and (doc.version != target_version or doc.content_hash != target_hash or job.target_fingerprint != current_fingerprint):
            job.status = "SUPERSEDED"; job.finished_at = now; job.locked_until = None
            await enqueue_document(db, doc, force=True)
            await db.commit()
            return
        job.last_error = error[:1000]
        status_code = exc.status_code if isinstance(exc, AIProviderError) else None
        error_type = exc.error_type if isinstance(exc, AIProviderError) else type(exc).__name__ if exc else "IndexingError"
        lowered = f"{error_type} {error}".lower()
        temporary = (status_code == 429 or status_code in {408, 425} or (status_code is not None and status_code >= 500)
                     or any(word in lowered for word in ("timeout", "connection", "temporarily unavailable", "networkerror", "service unavailable")))
        if temporary:
            # Temporary provider throttling/outages do not consume the bounded
            # permanent-document-failure budget.
            job.attempts = max(0, job.attempts - 1)
            job.retry_count = (job.retry_count or 0) + 1
            job.provider_error_type = str(error_type)[:120]
            retry_after = exc.retry_after_seconds if isinstance(exc, AIProviderError) else None
            delay = max(1, retry_after or settings.gemini_retry_seconds) if status_code == 429 else min(30 * (2 ** min(job.retry_count - 1, 4)), 300)
            job.status = "RETRYING"
            job.available_at = now + timedelta(seconds=delay)
            job.finished_at = None
            if doc and doc.version == target_version and doc.content_hash == target_hash and doc.freshness_status != Freshness.DELETED:
                doc.freshness_status = Freshness.RETRYING
                doc.ingestion_status = Ingestion.PENDING
                doc.indexing_error = ("Gemini quota reached. The document will retry automatically." if status_code == 429 else "Temporary embedding service issue. The document will retry automatically.")
                doc.indexing_failed_at = None
                doc.indexing_progress = 0
            db.add(AuditLog(user_id=None, action="INDEX_RETRY_SCHEDULED", resource=doc.title if doc else str(document_id), status="WAITING",
                            details={"job_id":str(job.id),"provider_error_type":str(error_type)[:120],"next_attempt_at":job.available_at.isoformat()}))
            await db.commit()
            return
        job.provider_error_type = str(error_type)[:120]
        job.locked_until = None
        if job.attempts < MAX_ATTEMPTS:
            job.status = "QUEUED"
            delay = RETRY_DELAYS[min(max(job.attempts - 1, 0), len(RETRY_DELAYS) - 1)]
            job.available_at = now + timedelta(seconds=delay)
            job.finished_at = None
            if doc and doc.version == target_version and doc.content_hash == target_hash and doc.freshness_status != Freshness.DELETED:
                doc.freshness_status = Freshness.QUEUED
                doc.ingestion_status = Ingestion.PENDING
                doc.indexing_error = error[:1000]
                doc.indexing_failed_at = None
                doc.indexing_progress = 0
        else:
            job.status = "FAILED"
            job.finished_at = now
            if doc and doc.version == target_version and doc.content_hash == target_hash and doc.freshness_status != Freshness.DELETED:
                doc.freshness_status = Freshness.FAILED
                doc.ingestion_status = Ingestion.FAILED
                doc.indexing_error = error[:1000]
                doc.indexing_failed_at = now
                doc.indexing_progress = 0
        if doc and doc.version == target_version and doc.content_hash == target_hash and doc.freshness_status != Freshness.DELETED:
            db.add(AuditLog(user_id=None, action="INDEX", resource=doc.title, status="ERROR",
                            details={"job_id": str(job.id), "attempt": job.attempts,
                                     "will_retry": job.attempts < MAX_ATTEMPTS,
                                     "error": error[:250]}))
        await db.commit()


async def _process(job_id):
    async with SessionLocal() as db:
        job = await db.get(IndexingJob, job_id)
        if not job:
            return
        document_id, target_version, target_hash = job.document_id, job.target_version, job.target_hash
        target_fingerprint = job.target_fingerprint or indexing_fingerprint(target_hash)
        doc = await db.scalar(select(Document).where(Document.id == document_id).with_for_update())
        if not doc or doc.freshness_status == Freshness.DELETED:
            job.status = "CANCELLED"; job.finished_at = datetime.now(timezone.utc)
            job.locked_until = None; await db.commit(); return
        if doc.version != target_version or doc.content_hash != target_hash or target_fingerprint != indexing_fingerprint(doc.content_hash):
            job.status = "SUPERSEDED"; job.finished_at = datetime.now(timezone.utc)
            job.locked_until = None; await db.commit()
            async with SessionLocal() as queue_db:
                current = await queue_db.get(Document, document_id)
                if current and current.freshness_status != Freshness.DELETED:
                    await enqueue_document(queue_db, current, force=True); await queue_db.commit()
            return
        path = doc.storage_path
        workspace_id, department, title = doc.workspace_id, doc.department, doc.title
        doc.freshness_status = Freshness.PROCESSING
        doc.ingestion_status = Ingestion.PENDING
        doc.indexing_error = None; doc.indexing_failed_at = None; doc.indexing_progress = 2
        job.progress = 2; job.started_at = datetime.now(timezone.utc)
        job.locked_until = datetime.now(timezone.utc) + timedelta(seconds=LEASE_SECONDS)
        await db.commit()
    heartbeat = asyncio.create_task(_heartbeat(job_id))
    try:
        if not path:
            raise FileNotFoundError("Stored document file path is unavailable")
        upload_root = Path(settings.upload_dir).resolve()
        source_path = Path(path).resolve()
        try:
            source_path.relative_to(upload_root)
        except ValueError:
            raise FileNotFoundError("Stored document is outside the upload directory")
        raw, stat = await asyncio.to_thread(lambda: (source_path.read_bytes(), source_path.stat()))
        actual_hash = hashlib.sha256(raw).hexdigest()
        if actual_hash != target_hash:
            await _mark_superseded(job_id, document_id, target_version, target_hash, actual_hash, stat)
            return
        await _set_progress(job_id, document_id, target_version, 10)
        source = await asyncio.to_thread(_read_and_extract, str(source_path))
        chunks = split_chunks(source.pages)
        if not chunks:
            raise ValueError("No readable text found in stored document")
        await _set_progress(job_id, document_id, target_version, 25)
        vectors = await embed([content for _, content in chunks], task_type="RETRIEVAL_DOCUMENT")
        if len(vectors) != len(chunks):
            raise ValueError("Embedding provider returned an incomplete result")
        await _set_progress(job_id, document_id, target_version, 90)
        now = datetime.now(timezone.utc)
        async with SessionLocal() as db:
            job = await db.get(IndexingJob, job_id)
            doc = await db.scalar(select(Document).where(Document.id == document_id).with_for_update())
            if not job or not doc or doc.freshness_status == Freshness.DELETED:
                if job:
                    job.status = "CANCELLED"; job.finished_at = now; job.locked_until = None
                await db.commit(); return
            if (doc.version != target_version or doc.content_hash != actual_hash or
                target_fingerprint != indexing_fingerprint(actual_hash)):
                job.status = "SUPERSEDED"; job.finished_at = now; job.locked_until = None
                await enqueue_document(db, doc, force=True); await db.commit(); return
            # New embeddings are ready. Deactivate previous vectors and add the complete
            # replacement set in this same transaction, keeping old citation rows intact.
            await db.execute(update(DocumentChunk).where(DocumentChunk.document_id == doc.id)
                             .values(embedding=None))
            for index, ((page, content), vector) in enumerate(zip(chunks, vectors)):
                db.add(DocumentChunk(document_id=doc.id, workspace_id=workspace_id,
                    department=department, chunk_index=index,
                    content=content, page_number=page, token_count=max(1, len(content)//4), embedding=vector))
            doc.indexed_content_hash = actual_hash
            doc.indexed_version = target_version
            doc.indexed_fingerprint = target_fingerprint
            doc.indexed_embedding_fingerprint = EMBEDDING_SPACE_FINGERPRINT
            doc.chunk_count = len(chunks)
            doc.storage_mtime_ns = stat.st_mtime_ns; doc.storage_size = stat.st_size
            doc.source_last_modified_at = datetime.fromtimestamp(stat.st_mtime, timezone.utc)
            doc.indexed_at = now; doc.last_verified_at = now
            doc.ingestion_status = Ingestion.INDEXED; doc.freshness_status = Freshness.FRESH
            doc.indexing_error = None; doc.indexing_failed_at = None; doc.indexing_progress = 100
            job.status = "SUCCEEDED"; job.progress = 100; job.last_error = None
            job.finished_at = now; job.locked_until = None
            if job.supersedes_document_id:
                old = await db.get(Document, job.supersedes_document_id)
                if old and old.freshness_status != Freshness.DELETED:
                    old.freshness_status = Freshness.DELETED
                    await db.execute(update(DocumentChunk).where(DocumentChunk.document_id == old.id).values(embedding=None))
            db.add(AuditLog(user_id=None, action="INDEX", resource=title, status="SUCCESS",
                            details={"job_id": str(job.id), "version": target_version,
                                     "content_hash": actual_hash, "chunk_count": len(chunks)}))
            old_path = job.old_storage_path
            await db.commit()
        if old_path and old_path != path:
            try:
                old = Path(old_path).resolve(); old.relative_to(upload_root); old.unlink(missing_ok=True)
            except (OSError, ValueError):
                log.warning("Could not remove replaced source file after indexing")
    except Exception as exc:
        message = _safe_indexing_error(exc)
        log.warning("Document indexing job %s failed (%s)",job_id,type(exc).__name__)
        try:
            await _fail_job(job_id, document_id, target_version, target_hash, message, exc)
        except Exception:
            log.exception("Could not persist indexing failure for job %s", job_id)
    finally:
        heartbeat.cancel()
        try:
            await heartbeat
        except asyncio.CancelledError:
            pass


async def _claim_job():
    now = datetime.now(timezone.utc)
    async with SessionLocal() as db:
        exhausted = (await db.scalars(select(IndexingJob).where(
            IndexingJob.status == "PROCESSING", IndexingJob.locked_until < now,
            IndexingJob.attempts >= MAX_ATTEMPTS).with_for_update(skip_locked=True).limit(50))).all()
        for job in exhausted:
            job.status = "FAILED"; job.finished_at = now; job.locked_until = None
            job.last_error = job.last_error or "Worker lease expired after maximum retries"
            await db.execute(update(Document).where(Document.id == job.document_id,
                Document.version == job.target_version,
                Document.freshness_status != Freshness.DELETED).values(
                    freshness_status=Freshness.FAILED, ingestion_status=Ingestion.FAILED,
                    indexing_error=job.last_error, indexing_failed_at=now, indexing_progress=0))
            doc = await db.get(Document, job.document_id)
            if doc:
                db.add(AuditLog(user_id=None, action="INDEX", resource=doc.title, status="ERROR",
                                details={"job_id": str(job.id), "attempt": job.attempts,
                                         "error": job.last_error[:250]}))
        if exhausted:
            await db.commit()
        job = await db.scalar(select(IndexingJob).where(or_(
            and_(IndexingJob.status.in_(["QUEUED", "RETRYING"]), IndexingJob.available_at <= now),
            and_(IndexingJob.status == "PROCESSING", IndexingJob.locked_until < now,
                 IndexingJob.attempts < MAX_ATTEMPTS)
        )).order_by(IndexingJob.available_at, IndexingJob.created_at)
          .with_for_update(skip_locked=True).limit(1))
        if not job:
            await db.rollback(); return None
        job.status = "PROCESSING"; job.locked_until = now + timedelta(seconds=LEASE_SECONDS)
        job.attempts += 1
        title = await db.scalar(select(Document.title).where(Document.id == job.document_id))
        db.add(AuditLog(user_id=None, action="INDEX_ATTEMPT", resource=title or str(job.document_id),
                        status="STARTED", details={"job_id": str(job.id), "attempt": job.attempts,
                                                    "target_version": job.target_version,
                                                    "target_fingerprint": job.target_fingerprint}))
        # _process owns attempt accounting for new jobs; the worker claim is the single
        # point that increments it, including recovery of expired leases.
        await db.commit()
        return job.id


async def scan_and_queue_stale():
    """Recover stale docs, content/config drift, missing vectors, and orphaned state."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=settings.freshness_sla_minutes)
    async with SessionLocal() as db:
        docs = (await db.scalars(select(Document).where(Document.freshness_status != Freshness.DELETED))).all()
        for doc in docs:
            if doc.source != "upload" or not doc.storage_path:
                continue
            active_job_status = await db.scalar(select(IndexingJob.status).where(
                IndexingJob.document_id == doc.id,
                IndexingJob.target_hash == doc.content_hash,
                IndexingJob.status.in_(["QUEUED", "PROCESSING", "RETRYING"])).limit(1))
            has_active = active_job_status is not None
            expected_fingerprint = indexing_fingerprint(doc.content_hash)
            active_chunks = await db.scalar(select(func.count(DocumentChunk.id)).where(
                DocumentChunk.document_id == doc.id, DocumentChunk.embedding.is_not(None))) or 0
            stale = doc.freshness_status == Freshness.STALE
            try:
                source_path = Path(doc.storage_path)
                stat = await asyncio.to_thread(source_path.stat)
                if doc.storage_mtime_ns != stat.st_mtime_ns or doc.storage_size != stat.st_size:
                    raw = await asyncio.to_thread(source_path.read_bytes)
                    digest = hashlib.sha256(raw).hexdigest()
                    if digest != doc.content_hash:
                        doc.content_hash = digest
                        doc.version += 1
                        stale = True
                    doc.storage_mtime_ns = stat.st_mtime_ns
                    doc.storage_size = stat.st_size
                    doc.source_last_modified_at = datetime.fromtimestamp(stat.st_mtime, timezone.utc)
            except OSError:
                stale = True
            if doc.freshness_status == Freshness.FRESH:
                stale = stale or (doc.indexed_version != doc.version or not doc.indexed_content_hash or doc.indexed_content_hash != doc.content_hash
                         or doc.indexed_fingerprint != expected_fingerprint or active_chunks != doc.chunk_count or active_chunks == 0
                         or (doc.last_verified_at is not None and doc.last_verified_at < cutoff))
            if doc.freshness_status in {Freshness.QUEUED, Freshness.PROCESSING, Freshness.RETRYING} and not has_active:
                stale = True
            if doc.freshness_status == Freshness.FAILED:
                # A terminal failure is retried automatically only when its inputs changed;
                # otherwise it remains visible for manual recovery instead of looping forever.
                job = await db.scalar(select(IndexingJob).where(
                    IndexingJob.document_id == doc.id, IndexingJob.target_hash == doc.content_hash)
                    .order_by(IndexingJob.created_at.desc()).limit(1))
                transient_previous_failure = bool(job and (job.provider_error_type in {"RateLimitError", "APIStatusError", "TimeoutError", "ConnectError"}
                    or any(fragment in (job.last_error or "").lower() for fragment in ("quota", "rate limit", "resource_exhausted"))))
                stale = not job or job.target_fingerprint != expected_fingerprint or transient_previous_failure
            if stale:
                if not has_active:
                    await enqueue_document(db, doc, force=doc.freshness_status == Freshness.FAILED)
                else:
                    doc.freshness_status = Freshness(active_job_status)
        await db.commit()


async def worker_loop():
    last_scan = 0.0
    while True:
        try:
            now = asyncio.get_running_loop().time()
            if now - last_scan >= SCAN_SECONDS:
                await scan_and_queue_stale()
                last_scan = now
            job_id = await _claim_job()
            if job_id:
                await _process(job_id)
            else:
                await asyncio.sleep(POLL_SECONDS)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Indexing queue worker iteration failed")
            await asyncio.sleep(POLL_SECONDS)
