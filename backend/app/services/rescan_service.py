"""Watchlist rescan orchestration.

Re-analyzes watchlist indicators (bypassing the freshness cache), appends a
history snapshot via the analysis pipeline, then evaluates every enabled alert
rule against the previous snapshot. Matching rules persist alert rows.
"""

from __future__ import annotations

from app.models.alerts import AlertRule
from app.models.watchlist import WatchlistItem
from app.repositories.registry_repository import RegistryRepository
from app.repositories.watchlist_repository import WatchlistRepository
from app.schemas.analysis import AnalysisResult
from app.schemas.watchlist import AlertOut, RescanOutcome, RescanReport
from app.services.alert_engine import SnapshotFacts, evaluate_rule
from app.services.analysis_service import AnalysisService


class RescanService:
    def __init__(
        self,
        analysis: AnalysisService,
        watchlist_repository: WatchlistRepository,
        registry_repository: RegistryRepository,
    ) -> None:
        self._analysis = analysis
        self._watchlist = watchlist_repository
        self._registry = registry_repository

    async def _facts_for(self, result: AnalysisResult | None) -> SnapshotFacts | None:
        if result is None:
            return None
        return SnapshotFacts(
            score=result.threat_score,
            level=result.threat_level,
            malicious=result.stats.malicious,
            suspicious=result.stats.suspicious,
        )

    async def rescan_item(self, item: WatchlistItem) -> RescanOutcome:
        try:
            result = await self._analysis.analyze_any(
                item.primary_type, item.value, force_refresh=True
            )
        except Exception as exc:  # preserve per-item failures in the report
            await self._watchlist.mark_checked(item.id)
            return RescanOutcome(
                watchlist_id=item.id,
                value=item.value,
                primary_type=item.primary_type,
                error=str(exc),
            )

        latest = await self._facts_for(result)

        history = await self._registry.snapshot_timeline(item.value, limit=2)
        previous_fact = None
        if len(history) >= 2:
            prev = history[1]
            previous_fact = SnapshotFacts(
                score=prev.threat_score,
                level=prev.threat_level,
                malicious=prev.malicious_count,
                suspicious=prev.suspicious_count,
            )
        elif len(history) == 1:
            prev = history[0]
            if prev.analysis_id != result.analysis_id:
                previous_fact = SnapshotFacts(
                    score=prev.threat_score,
                    level=prev.threat_level,
                    malicious=prev.malicious_count,
                    suspicious=prev.suspicious_count,
                )

        rules = await self._watchlist.list_rules()
        alerts: list[AlertOut] = []
        for rule in rules:
            candidate = evaluate_rule(rule, latest, previous_fact)
            if candidate is None:
                continue
            created = await self._watchlist.create_alert(
                watchlist_id=item.id,
                rule_id=candidate.rule_id,
                analysis_id=result.analysis_id,
                indicator=item.value,
                level=candidate.level,
                message=candidate.message,
            )
            alerts.append(
                AlertOut(
                    id=created.id,
                    watchlist_id=created.watchlist_id,
                    rule_id=created.rule_id,
                    analysis_id=created.analysis_id,
                    indicator=created.indicator,
                    level=created.level,
                    message=created.message,
                    seen=created.seen,
                    triggered_at=created.triggered_at,
                )
            )

        await self._watchlist.mark_checked(item.id)
        return RescanOutcome(
            watchlist_id=item.id,
            value=item.value,
            primary_type=item.primary_type,
            analysis_id=result.analysis_id,
            threat_score=result.threat_score,
            threat_level=result.threat_level,
            alerts=alerts,
        )

    async def rescan_all(self) -> RescanReport:
        items = await self._watchlist.enabled_items()
        outcomes = [await self.rescan_item(item) for item in items]
        return RescanReport(checked=len(outcomes), outcomes=outcomes)

    async def rescan_one(self, watchlist_id: str) -> RescanOutcome | None:
        item = await self._watchlist.get(watchlist_id)
        if item is None or not item.enabled:
            return None
        return await self.rescan_item(item)