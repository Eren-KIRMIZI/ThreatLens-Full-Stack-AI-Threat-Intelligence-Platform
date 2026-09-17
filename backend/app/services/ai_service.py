"""Evidence-based AI interpretation of a normalized analysis.

Bridges the normalized VirusTotal evidence to the OpenRouter LLM and guards
the result: the response must validate against the AI analysis schema and
every cited engine must really exist in the evidence (anti-hallucination).
"""

from __future__ import annotations

import json

from pydantic import ValidationError

from app.core.exceptions import AppException
from app.core.logging import get_logger
from app.schemas.ai import AIAnalysis
from app.schemas.analysis import AnalysisResult
from app.services.ai_prompts import SYSTEM_PROMPT, build_user_prompt
from app.services.openrouter_service import OpenRouterService

logger = get_logger(__name__)


def build_evidence(result: AnalysisResult) -> dict:
    """Serialize the analysis into a compact, JSON-safe evidence bundle.

    Raw file content never enters this payload: only normalized metadata.
    """
    data = result.model_dump(mode="json", exclude={"ai"})
    bundle = {
        "indicator": data["indicator"],
        "indicator_type": data["indicator_type"],
        "source": data["source"],
        "analyzed_at": data["analyzed_at"],
        "stats": data["stats"],
        "detections": data["detections"],
        "metadata": data["metadata"],
    }
    enrichment = data.get("enrichment")
    if enrichment:
        bundle["enrichment"] = {
            "confidence": enrichment.get("confidence", {}).get("overall"),
            "sources": enrichment.get("sources", []),
            "signals": (enrichment.get("confidence") or {}).get("reasons", []),
            "extra_observations": [
                {
                    "provider": item["provider"],
                    "type": item["evidence_type"],
                    "title": item["title"],
                    "value": item["value"],
                    "verdict": item["verdict"],
                }
                for item in enrichment.get("evidence", [])
                if item.get("provider") != "virustotal"
            ][:40],
        }
    return bundle


class AIService:
    """Transforms normalized evidence into a structured AI interpretation."""

    def __init__(self, openrouter: OpenRouterService) -> None:
        self._openrouter = openrouter

    async def interpret(self, result: AnalysisResult) -> AIAnalysis:
        evidence = json.dumps(build_evidence(result), ensure_ascii=False)
        raw = await self._openrouter.chat_json(
            system=SYSTEM_PROMPT,
            user=build_user_prompt(evidence),
        )

        try:
            ai = AIAnalysis.model_validate(raw)
        except ValidationError as exc:
            logger.error("ai response failed schema validation", error=str(exc))
            raise AppException(
                status_code=502,
                code="openrouter_invalid_response",
                message="The model response did not match the expected schema.",
                details=[{"field": e["loc"][0] if e["loc"] else "?", "message": e["msg"]} for e in exc.errors()],
            ) from exc

        # Anti-hallucination: only keep engine names that exist in the evidence.
        real_engines = {detection.engine for detection in result.detections}
        ai.evidence_refs = [ref for ref in ai.evidence_refs if ref in real_engines]
        ai.model = self._openrouter.model
        return ai