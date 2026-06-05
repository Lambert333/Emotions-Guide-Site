from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from backend.firebase_app import RealtimeDB


TEST_RESULTS_PATH = "Users/{user_id}/TestResults"
LEGACY_LOWERCASE_RESULTS_PATH = "users/{user_id}/test_results"

TEST_TYPE_NAMES = {
    "san": "САН",
    "emotional_intelligence": "Эмоциональный интеллект",
    "psm25_stress": "PSM-25 стресс",
    "spielberger_anxiety": "Тревожность Спилберга-Ханина",
    "boyko_burnout": "Выгорание Бойко",
    "maslach_burnout": "Выгорание Маслач",
    "self_esteem": "Самооценка",
    "mood_scale": "Шкала настроения",
}

SCORE_FIELDS = {
    "san": ["wellbeingScore", "activityScore", "moodScore"],
    "emotional_intelligence": ["ei_score"],
    "psm25_stress": ["total_score"],
    "spielberger_anxiety": ["situational_anxiety", "personal_anxiety"],
    "boyko_burnout": ["total_score", "tension_score", "resistance_score", "exhaustion_score"],
    "maslach_burnout": ["exhaustion_score", "depersonalization_score", "accomplishment_score"],
    "self_esteem": ["self_esteem_score"],
    "mood_scale": ["positive_affect", "negative_affect", "mood_balance"],
}

COMPATIBILITY_SCORE_FIELDS = ["wellbeingScore", "activityScore", "moodScore"]


def _results_path(user_id: str) -> str:
    return TEST_RESULTS_PATH.format(user_id=user_id)


def _legacy_lowercase_path(user_id: str) -> str:
    return LEGACY_LOWERCASE_RESULTS_PATH.format(user_id=user_id)


def _normalize_timestamp(timestamp: Any) -> int:
    if isinstance(timestamp, (int, float)):
        return int(timestamp)

    if isinstance(timestamp, str):
        try:
            return int(float(timestamp))
        except ValueError:
            try:
                return int(datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp() * 1000)
            except ValueError:
                pass

    return int(datetime.now().timestamp() * 1000)


def _numeric_or_zero(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _extract_scores(test_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
    fields = SCORE_FIELDS.get(test_type, [])
    return {field: data[field] for field in fields if field in data}


def _normalize_test_result(test_type: str, result_data: Dict[str, Any]) -> Dict[str, Any]:
    data = dict(result_data or {})
    timestamp = _normalize_timestamp(data.get("timestamp"))
    scores = data.get("scores") if isinstance(data.get("scores"), dict) else {}
    scores = {**_extract_scores(test_type, data), **scores}

    normalized = {
        "schemaVersion": 2,
        "testType": test_type,
        "testName": data.get("testName") or TEST_TYPE_NAMES.get(test_type, test_type),
        "timestamp": timestamp,
        "interpretation": data.get("interpretation", ""),
        "wellbeingScore": _numeric_or_zero(data.get("wellbeingScore")),
        "activityScore": _numeric_or_zero(data.get("activityScore")),
        "moodScore": _numeric_or_zero(data.get("moodScore")),
        "scores": scores,
    }

    return normalized


def _detect_legacy_test_type(result: Dict[str, Any]) -> str:
    test_type = result.get("testType")
    if test_type:
        return str(test_type)
    return "san"


def save_test_result(user_id: str, test_type: str, result_data: Dict[str, Any]) -> bool:
    if not user_id:
        raise ValueError("User ID is required.")

    normalized = _normalize_test_result(test_type, result_data)
    new_key = RealtimeDB.create(_results_path(user_id), normalized)
    return new_key is not None


def migrate_legacy_user_results(user_id: str) -> None:
    if not user_id:
        raise ValueError("User ID is required.")

    existing_results = RealtimeDB.get(_results_path(user_id)) or {}
    if isinstance(existing_results, dict):
        for result_id, result in existing_results.items():
            if not isinstance(result, dict):
                continue
            if result.get("schemaVersion") == 2 and result.get("testType"):
                continue

            test_type = _detect_legacy_test_type(result)
            normalized = _normalize_test_result(test_type, result)
            RealtimeDB.update(f"{_results_path(user_id)}/{result_id}", normalized)

    legacy_results = RealtimeDB.get(_legacy_lowercase_path(user_id)) or {}
    if not isinstance(legacy_results, dict) or not legacy_results:
        return

    for test_type, test_entries in legacy_results.items():
        if not isinstance(test_entries, dict):
            continue
        for legacy_id, legacy_result in test_entries.items():
            if not isinstance(legacy_result, dict):
                continue
            target_id = f"legacy_{test_type}_{legacy_id}"
            normalized = _normalize_test_result(str(test_type), legacy_result)
            RealtimeDB.set(f"{_results_path(user_id)}/{target_id}", normalized)

    RealtimeDB.delete(_legacy_lowercase_path(user_id))


def _all_results(user_id: str) -> Dict[str, Dict[str, Any]]:
    migrate_legacy_user_results(user_id)
    results = RealtimeDB.get(_results_path(user_id)) or {}
    return results if isinstance(results, dict) else {}


def _sorted_results(results: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized_results = []
    for result_id, result in results.items():
        if not isinstance(result, dict):
            continue
        item = dict(result)
        item["resultId"] = result_id
        item["timestamp"] = _normalize_timestamp(item.get("timestamp"))
        item["testType"] = _detect_legacy_test_type(item)
        normalized_results.append(item)

    return sorted(normalized_results, key=lambda item: item.get("timestamp", 0), reverse=True)


def get_san_results(user_id: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    results = [
        result
        for result in _sorted_results(_all_results(user_id))
        if result.get("testType") == "san"
    ]
    return results[:limit] if limit else results


def get_all_test_results_for_ai(user_id: str, limit: int = 25, per_test_type_limit: int = 5) -> List[Dict[str, Any]]:
    counts_by_type: Dict[str, int] = {}
    selected_results: List[Dict[str, Any]] = []

    for result in _sorted_results(_all_results(user_id)):
        test_type = result.get("testType", "unknown")
        if counts_by_type.get(test_type, 0) >= per_test_type_limit:
            continue

        selected_results.append(result)
        counts_by_type[test_type] = counts_by_type.get(test_type, 0) + 1

        if len(selected_results) >= limit:
            break

    return selected_results


def delete_san_results(user_id: str) -> int:
    deleted_count = 0
    for result in get_san_results(user_id):
        result_id = result.get("resultId")
        if not result_id:
            continue
        RealtimeDB.delete(f"{_results_path(user_id)}/{result_id}")
        deleted_count += 1
    return deleted_count


def build_ai_results_context(
    results: List[Dict[str, Any]],
    username: str,
    time_data: Dict[str, Any],
    interpretation_limit: int = 400,
) -> str:
    payload_results = []
    for result in results:
        interpretation = str(result.get("interpretation", ""))
        if len(interpretation) > interpretation_limit:
            interpretation = f"{interpretation[:interpretation_limit].strip()}..."

        payload_results.append({
            "testType": result.get("testType"),
            "testName": result.get("testName") or TEST_TYPE_NAMES.get(result.get("testType", ""), result.get("testType")),
            "timestamp": result.get("timestamp"),
            "wellbeingScore": result.get("wellbeingScore"),
            "activityScore": result.get("activityScore"),
            "moodScore": result.get("moodScore"),
            "scores": result.get("scores") or {},
            "interpretation": interpretation,
        })

    return json.dumps({
        "username": username,
        "has_results": bool(payload_results),
        "current": time_data,
        "tests": payload_results,
    }, ensure_ascii=False, separators=(",", ":"))


def build_chat_results_context(results: List[Dict[str, Any]], username: str, time_data: Dict[str, Any]) -> str:
    if not results:
        return ""

    return (
        "Контекст последних результатов тестов пользователя "
        f"{username}: {build_ai_results_context(results, username, time_data, interpretation_limit=180)}"
    )
