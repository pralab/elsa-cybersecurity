from models.utils import *
from .apk_downloader import APKDownloader
import os
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

    ts_round_dir = config.TS_ROUND_DIR
    ts_round_ds = config.TS_ROUND

    if config.DOWNLOAD_APKS:
        for i in range(1, 5):
            _download_apks(config.AZOO_API_KEY, ts_round_ds.format(i),
                           ts_round_dir.format(i), config.N_JOBS)

    results = []

    for i in range(1, 5):

        ts_round_i = sorted(
            [os.path.join(ts_round_dir.format(i), apk) for apk in
             os.listdir(ts_round_dir.format(i))], key=os.path.getctime)
        y_pred, scores = classifier.classify(ts_round_i)
        results.append({
            sha256: [int(y), float(s)] for sha256, y, s in zip(
                [os.path.basename(apk).split(".")[0] for apk in ts_round_i],
                y_pred, scores)})

    return results
