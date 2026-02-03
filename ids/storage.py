import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable


@dataclass
class Alert:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    alert_type: str
    severity: str
    details: str


@dataclass
class TrafficSample:
    timestamp: datetime
    protocol: str
    bytes_count: int


class Storage:
    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_db(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    details TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS traffic_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    bytes_count INTEGER NOT NULL
                )
                """
            )

    def save_alert(self, alert: Alert) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO alerts (
                    timestamp,
                    src_ip,
                    dst_ip,
                    protocol,
                    alert_type,
                    severity,
                    details
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.timestamp.isoformat(),
                    alert.src_ip,
                    alert.dst_ip,
                    alert.protocol,
                    alert.alert_type,
                    alert.severity,
                    alert.details,
                ),
            )

    def save_traffic_samples(self, samples: Iterable[TrafficSample]) -> None:
        rows = [
            (sample.timestamp.isoformat(), sample.protocol, sample.bytes_count)
            for sample in samples
        ]
        if not rows:
            return
        with self._connect() as connection:
            connection.executemany(
                """
                INSERT INTO traffic_samples (
                    timestamp,
                    protocol,
                    bytes_count
                ) VALUES (?, ?, ?)
                """,
                rows,
            )

    def fetch_recent_alerts(self, limit: int = 50) -> list[sqlite3.Row]:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                SELECT * FROM alerts
                ORDER BY datetime(timestamp) DESC
                LIMIT ?
                """,
                (limit,),
            )
            return list(cursor.fetchall())

    def fetch_alert_counts(self) -> list[sqlite3.Row]:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                SELECT alert_type, COUNT(*) AS count
                FROM alerts
                GROUP BY alert_type
                ORDER BY count DESC
                """
            )
            return list(cursor.fetchall())

    def fetch_traffic_summary(self, minutes: int = 30) -> list[sqlite3.Row]:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                SELECT
                    strftime('%H:%M', timestamp) AS bucket,
                    protocol,
                    SUM(bytes_count) AS bytes
                FROM traffic_samples
                WHERE timestamp >= datetime('now', ?)
                GROUP BY bucket, protocol
                ORDER BY bucket ASC
                """,
                (f"-{minutes} minutes",),
            )
            return list(cursor.fetchall())
