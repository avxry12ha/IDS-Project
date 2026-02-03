from __future__ import annotations

from dataclasses import dataclass


@dataclass
class InterceptionStatus:
    enabled: bool
    mode: str
    details: str


class HTTPSInterceptor:
    def __init__(self, enabled: bool, mode: str) -> None:
        self.enabled = enabled
        self.mode = mode
        self.status_message = "Passive TLS inspection only."

    def set_enabled(self, enabled: bool) -> None:
        self.enabled = enabled
        if not enabled:
            self.status_message = "HTTPS interception disabled."

    def set_mode(self, mode: str) -> None:
        self.mode = mode
        if mode == "lab" and self.enabled:
            self.status_message = (
                "Lab interception mode is enabled, but active MITM is not "
                "implemented in this prototype."
            )
        elif self.enabled:
            self.status_message = "Passive TLS inspection enabled."

    def status(self) -> InterceptionStatus:
        if not self.enabled:
            return InterceptionStatus(
                enabled=False,
                mode=self.mode,
                details="HTTPS interception disabled.",
            )
        if self.mode == "lab":
            return InterceptionStatus(
                enabled=True,
                mode=self.mode,
                details=(
                    "Lab interception mode enabled (passive logging only in this build)."
                ),
            )
        return InterceptionStatus(
            enabled=True,
            mode=self.mode,
            details="Passive TLS inspection enabled.",
        )
