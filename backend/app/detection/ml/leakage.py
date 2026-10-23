from collections import defaultdict


def entity_aware_split(rows: list[dict], test_ratio: float = 0.3) -> tuple[list[dict], list[dict]]:
    """Split by entity id so the same source never appears in train and test."""
    by_entity: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_entity[str(row["entity"])].append(row)
    entities = sorted(by_entity)
    if len(entities) < 3:
        return rows, []
    cut = max(1, int(len(entities) * (1 - test_ratio)))
    train_e, test_e = set(entities[:cut]), set(entities[cut:])
    train = [row for entity in train_e for row in by_entity[entity]]
    test = [row for entity in test_e for row in by_entity[entity]]
    overlap = {row["entity"] for row in train} & {row["entity"] for row in test}
    if overlap:
        raise RuntimeError("Leakage detected between train and test entities")
    return train, test
