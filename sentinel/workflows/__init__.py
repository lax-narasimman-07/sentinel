"""Workflow engine — composable multi-step security operations."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Awaitable

from sentinel.core.schemas import new_id, now_utc

logger = logging.getLogger("sentinel.workflows")


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    RETRYING = "retrying"


class WorkflowStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"


@dataclass
class StepResult:
    step_id: str
    status: StepStatus
    output: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    started_at: str = ""
    completed_at: str = ""


@dataclass
class StepDefinition:
    name: str
    handler: str
    params: dict[str, Any] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    retry_count: int = 0
    timeout_seconds: int = 300
    condition: str = ""


@dataclass
class WorkflowDefinition:
    name: str
    steps: list[StepDefinition] = field(default_factory=list)
    description: str = ""
    version: str = "1.0.0"


@dataclass
class WorkflowInstance:
    id: str
    workflow: str
    status: WorkflowStatus = WorkflowStatus.PENDING
    step_results: dict[str, StepResult] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    completed_at: str = ""


class WorkflowEngine:
    """Manages and executes security workflows."""

    def __init__(self) -> None:
        self._workflows: dict[str, WorkflowDefinition] = {}
        self._handlers: dict[str, Callable[..., Awaitable[dict[str, Any]]]] = {}
        self._instances: dict[str, WorkflowInstance] = {}

    def register_workflow(self, workflow: WorkflowDefinition) -> None:
        self._workflows[workflow.name] = workflow

    def register_handler(self, name: str, handler: Callable[..., Awaitable[dict[str, Any]]]) -> None:
        self._handlers[name] = handler

    def get_workflow(self, name: str) -> WorkflowDefinition | None:
        return self._workflows.get(name)

    def list_workflows(self) -> list[WorkflowDefinition]:
        return list(self._workflows.values())

    async def execute(self, workflow_name: str, context: dict[str, Any] | None = None) -> WorkflowInstance:
        workflow = self._workflows.get(workflow_name)
        if not workflow:
            raise ValueError(f"Workflow '{workflow_name}' not found")

        instance = WorkflowInstance(
            id=new_id(),
            workflow=workflow_name,
            context=context or {},
            created_at=now_utc(),
            status=WorkflowStatus.RUNNING,
        )
        self._instances[instance.id] = instance

        try:
            await self._execute_steps(workflow, instance)
            instance.status = WorkflowStatus.COMPLETED
        except Exception as e:
            instance.status = WorkflowStatus.FAILED
            logger.error(f"Workflow '{workflow_name}' failed: {e}")
        finally:
            instance.completed_at = now_utc()

        return instance

    async def _execute_steps(self, workflow: WorkflowDefinition, instance: WorkflowInstance) -> None:
        completed_steps = set()
        remaining_steps = list(workflow.steps)

        while remaining_steps:
            ready = []
            for step in remaining_steps:
                if all(dep in completed_steps for dep in step.depends_on):
                    ready.append(step)

            if not ready:
                remaining_steps = [s for s in remaining_steps if s.name not in completed_steps]
                if remaining_steps:
                    raise RuntimeError(f"Circular dependency detected: {[s.name for s in remaining_steps]}")
                break

            results = await asyncio.gather(
                *[self._execute_step(step, instance) for step in ready],
                return_exceptions=True,
            )

            for step, result in zip(ready, results):
                if isinstance(result, Exception):
                    instance.step_results[step.name] = StepResult(
                        step_id=step.name,
                        status=StepStatus.FAILED,
                        error=str(result),
                    )
                    raise result
                instance.step_results[step.name] = result
                completed_steps.add(step.name)
                remaining_steps.remove(step)

    async def _execute_step(self, step: StepDefinition, instance: WorkflowInstance) -> StepResult:
        handler = self._handlers.get(step.handler)
        if not handler:
            return StepResult(
                step_id=step.name,
                status=StepStatus.FAILED,
                error=f"Handler '{step.handler}' not found",
            )

        result = StepResult(step_id=step.name, status=StepStatus.RUNNING, started_at=now_utc())
        retries = 0

        while True:
            try:
                output = await asyncio.wait_for(
                    handler(**step.params, context=instance.context),
                    timeout=step.timeout_seconds,
                )
                result.output = output
                result.status = StepStatus.COMPLETED
                result.completed_at = now_utc()
                return result
            except asyncio.TimeoutError:
                result.error = f"Step timed out after {step.timeout_seconds}s"
                result.status = StepStatus.FAILED
                result.completed_at = now_utc()
                return result
            except Exception as e:
                retries += 1
                if retries > step.retry_count:
                    result.error = str(e)
                    result.status = StepStatus.FAILED
                    result.completed_at = now_utc()
                    return result
                result.status = StepStatus.RETRYING
                logger.warning(f"Step '{step.name}' failed (attempt {retries}/{step.retry_count}), retrying: {e}")
                await asyncio.sleep(min(2 ** retries, 30))

    async def cancel(self, instance_id: str) -> None:
        instance = self._instances.get(instance_id)
        if instance:
            instance.status = WorkflowStatus.CANCELLED
            instance.completed_at = now_utc()

    def get_instance(self, instance_id: str) -> WorkflowInstance | None:
        return self._instances.get(instance_id)

    def list_instances(self) -> list[WorkflowInstance]:
        return list(self._instances.values())
