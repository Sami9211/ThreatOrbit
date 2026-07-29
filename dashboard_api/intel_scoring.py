"""Composite intel score: how much should an analyst care about this indicator?

The store ranked indicators by `confidence` - a number copied verbatim from
whichever feed happened to write the row first. Every blocklist entry from every
feed therefore looked alike, and a value that nine independent sources agree on
sorted identically to one stale list's guess. That is the concrete reason a
310k-indicator store reads as an undifferentiated dump.

The score combines the things that actually distinguish indicators, and every
term is data we already hold:

  * **the feed's own claim, aged** - `ioc_lifecycle.effective_confidence`, which
    already decays per indicator type (a phishing URL dies in weeks, a file hash
    does not).
  * **source reliability** - an Admiralty-style grade per feed, applied as a
    multiplier. A curated malware tracker and a broad aggregation of unverified
    domains should not carry equal weight.
  * **corroboration** - how many INDEPENDENT sources assert the value. This is
    the signal a multi-feed platform exists to produce and the one thing a
    single public feed cannot give you.
  * **local sightings** - whether this deployment has actually seen the value in
    its own telemetry. Nothing a third party asserts outranks the customer's own
    logs, so this is weighted above every other term.
  * **attribution** - whether it arrived attached to a report/actor rather than
    as a bare value in a list.

Every score is returned WITH its components. A ranking an analyst cannot
interrogate is a ranking they are right not to trust, and "why is this 84?" has
to be answerable in the UI rather than in the source.
"""
from dashboard_api.ioc_lifecycle import effective_confidence

# Admiralty source reliability (A most reliable .. F cannot be judged), applied
# as a multiplier on the feed's own claim rather than as a flat bonus: an
# unreliable source asserting 90% confidence should not outrank a reliable one
# asserting 70%.
RELIABILITY_WEIGHT = {
    "A": 1.00,   # completely reliable
    "B": 0.92,   # usually reliable
    "C": 0.82,   # fairly reliable (default for an ungraded feed)
    "D": 0.68,   # not usually reliable
    "E": 0.50,   # unreliable
    "F": 0.40,   # reliability cannot be judged
}
DEFAULT_RELIABILITY = "C"

# Corroboration. Front-loaded and capped: the jump from one source to two is the
# most informative step by far, and the tenth adds very little - twenty feeds
# copying the same upstream list is not twenty independent confirmations. The
# curve is deliberately steeper at the start than across the rest of its range.
CORROBORATION_FIRST = 16     # 1 -> 2 sources, the single most informative step
CORROBORATION_EXTRA = 4      # each further independent source
CORROBORATION_CAP = 26

# A value seen in THIS deployment's telemetry outranks anything a feed claims,
# because it is the only evidence that concerns this network specifically. The
# first sighting alone therefore has to beat a FULLY corroborated value that has
# never been seen here - so it starts above CORROBORATION_CAP by construction.
SIGHTING_FIRST = CORROBORATION_CAP + 6
SIGHTING_EXTRA = 4
SIGHTING_CAP = 44

# Arrived with a report/actor attached rather than as a bare row in a list.
ATTRIBUTION_BONUS = 8


def _corroboration_bonus(source_count: int) -> int:
    """2 -> 16, 3 -> 20, 4 -> 24, 5 -> 26 (capped), flat thereafter."""
    if source_count < 2:
        return 0
    return min(CORROBORATION_CAP,
               CORROBORATION_FIRST + (source_count - 2) * CORROBORATION_EXTRA)


def _sighting_bonus(sightings: int) -> int:
    if sightings < 1:
        return 0
    return min(SIGHTING_CAP, SIGHTING_FIRST + (sightings - 1) * SIGHTING_EXTRA)


def score_indicator(ioc: dict, *, source_count: int = 1,
                    reliability: str = DEFAULT_RELIABILITY,
                    local_sightings: int = 0, now=None) -> dict:
    """Score one indicator 0-100, with the reasoning that produced it.

    `ioc` is a row from the IOC store. `source_count` is how many independent
    sources assert the value (see observable_sources), `local_sightings` how
    many times it has been seen in this deployment's own telemetry.
    """
    grade = (reliability or DEFAULT_RELIABILITY).upper()[:1]
    weight = RELIABILITY_WEIGHT.get(grade, RELIABILITY_WEIGHT[DEFAULT_RELIABILITY])

    aged = effective_confidence(ioc.get("confidence") or 0, ioc.get("last_seen"),
                                ioc.get("type"), now)
    base = int(round(aged * weight))

    corroboration = _corroboration_bonus(max(1, source_count))
    sighting = _sighting_bonus(local_sightings)
    attribution = ATTRIBUTION_BONUS if (ioc.get("report_id") or ioc.get("actor")) else 0

    raw = base + corroboration + sighting + attribution
    total = max(0, min(100, raw))

    components = [{
        "label": "Source claim, aged",
        "delta": base,
        "why": f"{ioc.get('confidence') or 0}% asserted, decayed to {aged}% by age, "
               f"weighted x{weight:.2f} for a grade-{grade} source",
    }]
    if corroboration:
        components.append({
            "label": "Corroboration",
            "delta": corroboration,
            "why": f"{source_count} independent sources assert this value",
        })
    if sighting:
        components.append({
            "label": "Seen in your environment",
            "delta": sighting,
            "why": f"observed {local_sightings}x in this deployment's own telemetry",
        })
    if attribution:
        components.append({
            "label": "Attributed",
            "delta": attribution,
            "why": f"arrived with {'a report' if ioc.get('report_id') else 'an actor'} attached",
        })

    if raw > total:
        # Without this the parts do not add up to the whole, and an explanation
        # that does not reconcile is worse than none - it looks like a bug.
        components.append({
            "label": "Capped",
            "delta": total - raw,
            "why": f"the parts total {raw}; the scale stops at 100",
        })

    return {
        "score": total,
        "band": band_for(total),
        "components": components,
        "sourceCount": source_count,
        "reliability": grade,
    }


def band_for(score: int) -> str:
    """Coarse band for colour/sorting. Deliberately NOT called severity: severity
    is about what the thing would DO, this is about how much we believe it."""
    if score >= 75:
        return "high"
    if score >= 50:
        return "moderate"
    if score >= 25:
        return "low"
    return "weak"
