"""Decorator-based guard for wrapping AI-calling functions."""

import asyncio
import functools
from collections.abc import Callable
from typing import ParamSpec, TypeVar

from vindicara.sdk.exceptions import VindicaraPolicyViolation

P = ParamSpec("P")
R = TypeVar("R")


def guard(
    policy: str = "content-safety",
    api_key: str = "",
    offline: bool = True,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator that evaluates function output against a Vindicara policy.

    Usage:
        @vindicara.guard(policy="content-safety")
        async def generate_response(prompt: str) -> str:
            return await llm.chat(prompt)

        @vindicara.guard(policy="pii-filter")
        def generate_sync(prompt: str) -> str:
            return llm.chat_sync(prompt)
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                from vindicara.sdk.client import VindicaraClient

                client = VindicaraClient(api_key=api_key, offline=offline)
                result = await func(*args, **kwargs)  # type: ignore[misc]
                output_text = str(result)
                input_text = str(args[0]) if args else ""
                guard_result = await client.async_guard(
                    input=input_text,
                    output=output_text,
                    policy=policy,
                )
                if guard_result.is_blocked:
                    raise VindicaraPolicyViolation(
                        message=f"Output blocked by policy '{policy}'",
                        policy_id=policy,
                    )
                return result

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            from vindicara.sdk.client import VindicaraClient

            client = VindicaraClient(api_key=api_key, offline=offline)
            result = func(*args, **kwargs)
            output_text = str(result)
            input_text = str(args[0]) if args else ""
            guard_result = client.guard(
                input=input_text,
                output=output_text,
                policy=policy,
            )
            if guard_result.is_blocked:
                raise VindicaraPolicyViolation(
                    message=f"Output blocked by policy '{policy}'",
                    policy_id=policy,
                )
            return result

        return sync_wrapper  # type: ignore[return-value]

    return decorator
