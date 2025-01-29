from .feature_space_attack import FeatureSpaceAttack
from models.utils import *
import logging


def evaluate(classifier, config):

    results = []

    features_fp_check = load_features(config.FEATURES_TS_FP_CHECK)
    y_pred, scores = classifier.predict(features_fp_check)

    results.append({
        sha256: [int(y), float(s)] for sha256, y, s in zip(
            load_sha256_list(config.FEATURES_TS_FP_CHECK),
            y_pred, scores)})

    malware_features = load_features(config.FEATURES_TS_ADV)
    y_pred, scores = classifier.predict(malware_features)

    results.append({
        sha256: [int(y), float(s)] for sha256, y, s in zip(
            load_sha256_list(config.FEATURES_TS_ADV),
            y_pred, scores)})

    attack = FeatureSpaceAttack(classifier=classifier,
                                logging_level=logging.INFO)

    y_tr = load_labels(config.FEATURES_TR, config.TR)

    for n_feats in [25, 50, 100]:
        goodware_features = (
            sample for sample, label in zip(load_features(
            config.FEATURES_TR), y_tr) if label == 0)
        malware_features = load_features(config.FEATURES_TS_ADV)
        adv_examples = attack.run(
            malware_features, goodware_features, n_iterations=100,
            n_features=n_feats, n_candidates=50)
        y_pred, scores = classifier.predict(adv_examples)
        results.append({
            sha256: [int(y), float(s)] for sha256, y, s in zip(
                load_sha256_list(config.FEATURES_TS_ADV),
                y_pred, scores)})

    return results
