"""Unit tests for the evidence-based threat scoring rubric."""

import pytest

from app.schemas.analysis import DetectionStats
from app.services.scoring import compute_score, level_for_score


@pytest.mark.parametrize(
    "stats,reputation,votes,expected",
    [
        (DetectionStats(), None, None, (0, "clean")),
        (DetectionStats(malicious=1), None, None, (10, "clean")),
        (DetectionStats(malicious=2), None, None, (20, "suspicious")),
        (
            DetectionStats(malicious=5, suspicious=2),
            -10,
            {"malicious": 3, "harmless": 0},
            (61, "malicious"),
        ),
        (DetectionStats(suspicious=5), None, None, (20, "suspicious")),
        (
            DetectionStats(malicious=20),
            -500,
            {"malicious": 10, "harmless": 0},
            (100, "critical"),
        ),
        (
            DetectionStats(),
            +100,
            {"malicious": 0, "harmless": 80},
            (0, "clean"),
        ),
    ],
)
def test_compute_score(stats, reputation, votes, expected) -> None:
    assert compute_score(stats, reputation=reputation, total_votes=votes) == expected


def test_level_band_boundaries() -> None:
    assert level_for_score(0) == "clean"
    assert level_for_score(19) == "clean"
    assert level_for_score(20) == "suspicious"
    assert level_for_score(39) == "suspicious"
    assert level_for_score(40) == "malicious"
    assert level_for_score(69) == "malicious"
    assert level_for_score(70) == "critical"
    assert level_for_score(100) == "critical"


def test_score_is_never_outside_range() -> None:
    huge = DetectionStats(malicious=10_000, suspicious=10_000)
    assert compute_score(huge) == (100, "critical")


def test_negative_reputation_raises_score() -> None:
    normal = compute_score(DetectionStats(malicious=3))[0]
    with_reputation = compute_score(
        DetectionStats(malicious=3), reputation=-1000
    )[0]
    assert with_reputation > normal