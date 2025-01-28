from models.utils import *


def evaluate(classifier, config):
    results = []

    for i in range(1, 5):
        features_ts = load_features(config.FEATURES_TS_ROUND.format(i))
        y_pred, scores = classifier.predict(features_ts)
        results.append({
            sha256: [int(y), float(s)] for sha256, y, s in zip(
                load_sha256_list(config.FEATURES_TS_ROUND.format(i)),
                y_pred, scores)})

    return results
