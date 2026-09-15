"""Job system — async job management for long-running tool executions."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Callable, Awaitable

from omega.core.schemas import Job, JobStatus, ToolResult, new_id, now_utc
from omega.storage import Database
from omega.tools import ToolExecutor, ToolExecutionRequest

logger = logging.getLogger("omega.jobs")


class JobManager:
    """Manages async jobs with status tracking, retry, and cancellation."""

    def __init__(self, db: Database, executor: ToolExecutor) -> None:
        self.db = db
        self.executor = executor
        self._running: dict[str, asyncio.Task[None]] = {}

    async def submit(self, engagement_id: str, tool_name: str, target: str, parameters: dict[str, Any] | None = None, timeout: float = 300) -> Job:
        job = Job(
            id=new_id(), engagement_id=engagement_id, tool_name=tool_name,
            target=target, parameters=parameters or {}, timeout_seconds=timeout,
            status=JobStatus.QUEUED, created_at=now_utc(), updated_at=now_utc(),
        )
        await self.db.save_job(job.model_dump())
        return job

    async def start(self, job_id: str) -> Job | None:
        data = await self.db.get_job(job_id)
        if not data:
            return None
        job = Job(**data)
        if job.status not in (JobStatus.QUEUED,):
            return job

        job.status = JobStatus.RUNNING
        job.started_at = now_utc()
        await self.db.save_job(job.model_dump())

        task = asyncio.create_task(self._run_job(job))
        self._running[job_id] = task
        return job

    async def submit_and_run(self, engagement_id: str, tool_name: str, target: str, parameters: dict[str, Any] | None = None, timeout: float = 300) -> Job:
        job = await self.submit(engagement_id, tool_name, target, parameters, timeout)
        await self.start(job.id)
        result = await self.wait(job.id, timeout + 30)
        return result or job

    async def _run_job(self, job: Job) -> None:
        try:
            request = ToolExecutionRequest(
                tool_name=job.tool_name, target=job.target,
                parameters=job.parameters, engagement_id=job.engagement_id,
                timeout_seconds=job.timeout_seconds,
            )
            result = await asyncio.wait_for(
                self.executor.execute(request, job.engagement_id),
                timeout=job.timeout_seconds,
            )
            job.result = result
            job.status = JobStatus.COMPLETED if result.success else JobStatus.FAILED
            job.error = result.error
            job.completed_at = now_utc()
        except asyncio.TimeoutError:
            job.status = JobStatus.TIMED_OUT
            job.error = f"Job timed out after {job.timeout_seconds}s"
            job.completed_at = now_utc()
        except Exception as e:
            job.status = JobStatus.FAILED
            job.error = str(e)
            job.completed_at = now_utc()
            logger.exception(f"Job {job.id} failed")

        await self.db.save_job(job.model_dump())
        self._running.pop(job.id, None)

    async def cancel(self, job_id: str) -> bool:
        task = self._running.get(job_id)
        if task and not task.done():
            task.cancel()
            data = await self.db.get_job(job_id)
            if data:
                data["status"] = JobStatus.CANCELLED
                data["updated_at"] = now_utc().isoformat()
                await self.db.save_job(data)
            self._running.pop(job_id, None)
            return True
        return False

    async def wait(self, job_id: str, timeout: float = 10) -> Job | None:
        task = self._running.get(job_id)
        if task:
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass
        data = await self.db.get_job(job_id)
        return Job(**data) if data else None

    async def get_status(self, job_id: str) -> Job | None:
        data = await self.db.get_job(job_id)
        return Job(**data) if data else None

    async def list_jobs(self, engagement_id: str, status: str | None = None) -> list[Job]:
        rows = await self.db.list_jobs(engagement_id, status)
        return [Job(**r) for r in rows]

    async def retry(self, job_id: str) -> Job | None:
        data = await self.db.get_job(job_id)
        if not data:
            return None
        job = Job(**data)
        if job.retry_count >= job.max_retries:
            return job
        job.retry_count += 1
        job.status = JobStatus.QUEUED
        job.error = None
        job.result = None
        await self.db.save_job(job.model_dump())
        return await self.start(job.id)
