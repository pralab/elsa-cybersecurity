from .problem_space_attack import ProblemSpaceAttack
from .apk_downloader import APKDownloader
import os
import logging
import pandas as pd
from zipfile import ZipFile, ZIP_DEFLATED


def _download_apks(androzoo_api_key, ds_file, out_dir, n_jobs=1):
    n_jobs = min(n_jobs, 20)
    downloader = APKDownloader(androzoo_api_key, out_dir)
    with ZipFile(ds_file, "r", ZIP_DEFLATED) as z:
        ds_csv = pd.concat(
            [pd.read_csv(z.open(f))[["sha256"]]
             for f in z.namelist()], ignore_index=True)
        apks_sha256 = ds_csv.sha256.values.tolist()
    downloader.download_apks(apks_sha256, n_jobs=n_jobs)


def evaluate(classifier, config):
    ts_fp_check_dir = config.TS_FP_CHECK_DIR
    ts_adv_dir = config.TS_ADV_DIR
    manipulated_apks_dir = config.MANIPULATED_APKS_DIR

    if config.DOWNLOAD_APKS:
        ts_fp_check_ds = config.TS_FP_CHECK
        _download_apks(
            config.AZOO_API_KEY, ts_fp_check_ds, ts_fp_check_dir, config.N_JOBS)
        ts_adv_ds = config.TS_ADV
        _download_apks(
            config.AZOO_API_KEY, ts_adv_ds, ts_adv_dir, config.N_JOBS)

    results = []

    ts_fp_check = sorted(
        [os.path.join(ts_fp_check_dir, apk) for apk in
         os.listdir(ts_fp_check_dir)], key=os.path.getctime)
    y_pred, scores = classifier.classify(ts_fp_check)

    results.append({
        sha256: [int(y), float(s)] for sha256, y, s in zip(
            [os.path.basename(apk).split(".")[0] for apk in ts_fp_check],
            y_pred, scores)})

    ts_adv = sorted([os.path.join(ts_adv_dir, apk) for apk in
                     os.listdir(ts_adv_dir)], key=os.path.getctime)
    y_pred, scores = classifier.classify(ts_adv)

    results.append({
        sha256: [int(y), float(s)] for sha256, y, s in zip(
            [os.path.basename(apk).split(".")[0] for apk in ts_adv],
            y_pred, scores)})

    attack = ProblemSpaceAttack(classifier=classifier,
                                manipulated_apks_dir=manipulated_apks_dir,
                                logging_level=logging.INFO)

    adv_results = attack.run(ts_adv, ts_fp_check, n_iterations=5,
                             n_features=100, n_jobs=config.N_JOBS,
                             n_candidates=20)

    results.append({sha256: [int(adv_result[0]), float(adv_result[1])]
                    for sha256, adv_result in zip(
            [os.path.basename(apk).split(".")[0] for apk in ts_adv],
            adv_results)})

    return results
