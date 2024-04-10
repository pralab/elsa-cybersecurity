from feature_space_attack import FeatureSpaceAttack
from models.utils import *
import os
import logging


def evaluate(classifier):
    base_path = os.path.join(os.path.dirname(__file__))

    results = []

    features_fp_check = load_features(
            os.path.join(base_path, "../data/test_set_fp_check_features.zip"))
    y_pred, scores = classifier.predict(features_fp_check)

    results.append({
        sha256: [int(y), float(s)] for sha256, y, s in zip(
            load_sha256_list(os.path.join(
                base_path, f"../data/test_set_fp_check_features.zip")),
            y_pred, scores)})

    malware_features = load_features(
        os.path.join(base_path, "../data/test_set_adv_features.zip"))
    y_pred, scores = classifier.predict(malware_features)

    results.append({
        sha256: [int(y), float(s)] for sha256, y, s in zip(
            load_sha256_list(os.path.join(
                base_path, f"../data/test_set_adv_features.zip")),
            y_pred, scores)})

    attack = FeatureSpaceAttack(classifier=classifier,
                                logging_level=logging.INFO)

    y_tr = load_labels(
        os.path.join(base_path, "../data/training_set_features.zip"),
        os.path.join(base_path, "../data/training_set.zip"))

    for n_feats in [25, 50, 100]:
        goodware_features = (
            sample for sample, label in zip(load_features(
            os.path.join(base_path, "../data/training_set_features.zip")),
            y_tr) if label == 0)
        malware_features = load_features(
            os.path.join(base_path, "../data/test_set_adv_features.zip"))
        adv_examples = attack.run(
            malware_features, goodware_features, n_iterations=100,
            n_features=n_feats, n_candidates=50)
        y_pred, scores = classifier.predict(adv_examples)
        results.append({
            sha256: [int(y), float(s)] for sha256, y, s in zip(
                load_sha256_list(os.path.join(
                    base_path, f"../data/test_set_adv_features.zip")),
                y_pred, scores)})

    return results
