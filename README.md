# elsa-cybersecurity
Official repository for the [Cybersecurity use case](https://benchmarks.elsa-ai.eu/?ch=6) of [ELSA](https://www.elsa-ai.eu/) EU Project.

## TL;DR: How to participate
1. Read the [competition rules](#competition-rules).
2. Download the [datasets](#datasets) and store them in the `data` folder.
3. Implement your detector (follow the instructions [here](#model-implementation-instructions)).
4. Run the [provided code](#evaluation-instructions) to produce the evaluation results and submit them [here](https://benchmarks.elsa-ai.eu/?ch=6&com=mymethods).

**SaTML Competition Deadline: March 31, 2025 at 23:59 AoE.**

## Overview

The Cybersecurity use case aims to evaluate machine learning methods when they are used as a first line of defense against malicious software (malware). The considered use cases focused on detecting malware for the Android Operating System. On this task, machine learning usually performs well, learning common patterns from data and enabling the detection of potentially never-before-seen malware samples. However, it has been shown that those detectors (i) tend to exhibit a rapid performance decay over time due to the natural evolution of samples and (ii) can be bypassed by slightly manipulating malware samples in an adversarial manner. The practical impact of these two issues is that current learning-based malware detectors need constant updates and retraining on newly collected and labeled data.

We propose a threefold benchmark to provide tools for comparing AI-based Android malware detectors in a realistic setting. They challenge the research community to go beyond simplistic assumptions to ultimately design more robust AI models that can be maintained and updated more efficiently, saving human labor and effort. The competition is structured in three separate tracks:

### Track 1: Adversarial Robustness to Feature-space Attacks
In this scenario, we aim to measure how much the models' predictions change against increasing amounts of adversarial manipulations, assuming the attacker knows the features used and the model itself and has unrestricted access to it. A feature-space evasion attack will be performed on test applications, perturbing the feature vector with constraints to ensure that applying these manipulations to an APK preserves its malicious functionalities. The applied perturbation is bounded based on the number of modified features.

### Track 2: Adversarial Robustness to Problem-space Attacks
The problem-space attack scenario consists of manipulating the APK files directly rather than only simulating the effect of the attack at the feature level. In this case, we assume the attacker does not know the target model and its features. An input-space evasion attack will be performed on the test applications, applying functionality-preserving manipulation to the APKs. The applied perturbation is bounded based on the number of modified features.

### Track 3: Temporal Robustness to Data Drift
In this setting, we will collect the performance evaluation of the given AI-based detectors with respect to (future) data collected over time, updating the test applications with new samples in each evaluation round.

## Competition Rules

### General rules
1. The binary classification task consists of distinguishing malware samples from benign applications, only relying on ML-based approaches. 
2. The use of whitelisting, blacklisting, or signatures is not allowed.
3. The submitted models can only rely on statically extracted features, i.e., applications must not be executed during the feature extraction process.
4. Participants must train their models only on the provided training dataset. 
5. The submitted model must be evaluated only with the provided code.
6. Everything must be fully reproducible. The participants must provide all the required code to train and deploy their models, including pre-trained models and the feature extraction process (except for Track 1, where the features will be provided to the participants) and, if necessary, the pre-set random seeds to guarantee more accurate reproducibility. All submitted models and results are subject to re-evaluations. All the provided material will be kept private until the end of the competition and made public after the winners are announced.
7. You can participate independently in each of the three evaluation tracks. Participation in all three tracks is not mandatory.

### Track 1: Adversarial Robustness to Feature-space Attacks
1. The submitted models must only rely on the provided feature set or a custom subset thereof (in this case, the user must specify the selected features). 
2. The submitted models must accept feature vectors as input and provide the classification score of the positive class and the predicted class labels as output. 
3. The submitted models must have a False Positive Rate equal to or lower than 1% on the provided validation set composed of benign samples only.
4. The winner will be the one with the highest Detection Rate when 100 features are manipulated. If multiple participants report the same score, the other metrics will be considered in this order to determine the winner: Detection Rate when 50 features are manipulated, Detection Rate when 25 features are manipulated, Detection Rate in the absence of manipulation, False Positive Rate.

### Track 2: Adversarial Robustness to Problem-space Attacks
1. The submitted models must accept APK files as input and provide the classification scores of the positive class and the predicted class labels as output. 
2. The submitted models must have a False Positive Rate equal to or lower than 1% on the provided validation set composed of benign samples only.
3. The winner will be the one with the highest Detection Rate when 100 features are manipulated. If multiple participants report the same score, the other metrics will be considered in this order to determine the winner: Detection Rate in the absence of manipulation, False Positive Rate.

### Track 3: Temporal Robustness to Data Drift
1. The submitted models must accept APK files as input and provide the classification scores of the positive class and the predicted class labels as output.
2. The winner will be the one with the highest Area Under Time. If multiple participants report the same score, they will be considered joint winners.

## Datasets

**TL;DR: All the datasets can be downloaded [here](https://benchmarks.elsa-ai.eu/?ch=6&com=downloads) (registration is required).**

We release a training set composed of 75K applications sampled between 2017-01-01 and 2019-12-31, with 25K applications per year.

For Tracks 1 and 3, we provide two test sets sampled between 2020-01-01 and 2022-06-30, composed of 5000 goodware and 1250 malware applications, respectively.

For Track 3, we provide 4 test sets with applications sampled between 2020-01-01 and 2022-06-30, with 12,5K applications per semester.

![](https://github.com/pralab/elsa-cybersecurity/blob/main/assets/datasets_elsa.png?raw=true)

We sample the datasets from the AndroZoo [1] repository, a growing collection of Android Applications collected from several sources that at the moment contains more than 20 million samples. On the chosen samples, we then collect analysis reports from VirusTotal, from which we extract a timestamp (from the first_submission_date field) and a binary label. A negative label is assigned to those samples that have no detections from the VirusTotal [2] antimalware engines, whereas a positive label is assigned to those samples that are detected by at least 10 antimalware engines. We exclude samples with a number of detections between 1 and 9 in order to discard potentially false positives and grayware applications.

We release the SHA256 hashes of the APK that the participants should consider, in CSV format. They should download the corresponding APKs from the [AndroZoo](https://androzoo.uni.lu/) public repository (after obtaining the API key, which will be granted to everyone affiliated with a university/research institution). The participants must strictly follow the [AndroZoo Access Conditions](https://androzoo.uni.lu/access).

Together with the APK hashes, we provide the application timestamp and (for the training set only) label in the CSV files.

### Pre-computed Features
In addition, for all the released datasets, we also provide the extracted features from the DREBIN [3] feature set in the form of JSON files (one for each APK sample) that are structured as follows:

```
{
  feature_type: [feature1, feature2, …],
  …
}
```

The feature types (and the corresponding feature sets from DREBIN) are:

- features: S1 Hardware components
- req_permissions: S2 Requested permissions
- activities, services, providers, receivers: S3 App components
- intent_filters: S4 Filtered intents
- api_calls: S5 Restricted API calls
- used_permissions: S6 Used permissions
- suspicious_calls: S7 Suspicious API calls
- urls: S8 Network addresses

The pre-computed features can be downloaded [here](https://benchmarks.elsa-ai.eu/?ch=6&com=downloads) (registration is required).

## Model implementation instructions
Please, follow these instructions when implementing your detector:
- The model class must necessarily implement the interface defined in the [BaseModel](https://github.com/pralab/android-detectors/blob/main/src/models/base/base_model.py) class. We suggest to extend this class.
- Provide a Python module containing a `load()` method that returns an instance of your trained classifier.
- To ensure reproducibility and allow validating the results, make sure to set all random seeds, add all the requirements, and if necessary a Dockerfile from where to run the evaluation scripts.

In [this repository](https://github.com/pralab/android-detectors) you can find already implemented models which serve as baselines for the benchmarks hosted in the Cybersecurity Use Case.

## Evaluation Instructions

- Create a Python environment and install all the requirements:
```bash
pip install -r track_1/attack_requirements.txt
pip install -r track_2/attack_requirements.txt
pip install -r track_2/problem_space_attack/manipulation/Obfuscapk/src/requirements.txt
```

- Read and edit (if needed) the [configuration file](https://github.com/pralab/elsa-cybersecurity/blob/main/config.py).

- Run the `main.py` script passing the path of the Python module loading your detector, the number of the evaluation tracks for which to produce the results and the name of your approach:
```bash
python main.py --clf_loader_path <your_loader_path.py> --track <track number> --method_name <your method name>
```

- Pick the produced file from the `submission` directory and upload it [here](https://benchmarks.elsa-ai.eu/?ch=6&com=mymethods).

If you use Docker, you can run the following commands:
```bash
docker build -t android <your Dockerfile path>
docker run -itd --name android android
docker cp . android:/
docker exec -it android pip install -r /track1/attack_requirements.txt
docker exec -it android pip install -r /track2/attack_requirements.txt
docker exec -it android pip install -r /track_2/problem_space_attack/manipulation/Obfuscapk/src/requirements.txt
docker exec -it android python main.py --clf_loader_path <your_loader_path.py> --track <track number> --method_name <your method name>
docker cp android:/submissions/* submissions/
docker stop android
```

### Submission Examples

These commands can be used to produce the submission files for DREBIN classifier.

Download the training dataset, the Track 1 datasets and their pre-extracted features from the [ELSA benchmarks website](https://benchmarks.elsa-ai.eu/?ch=6&com=downloads) inside the `data` directory.

It is recommended to create a new environment. In this example we use conda (it might be required to append `android-detectors/src` directory to the python path before launching the script).
```bash
conda create -n android python=3.9
conda activate android
pip install -r android-detectors/requirements.txt
pip install -r track_1/attack_requirements.txt
pip install -r track_2/attack_requirements.txt
pip install -r track_2/problem_space_attack/manipulation/Obfuscapk/src/requirements.txt
export PYTHONPATH="${PYTHONPATH}:android-detectors/src"
python main.py --clf_loader_path android-detectors/src/loaders/drebin_loader.py --track 1 --method_name drebin
python main.py --clf_loader_path android-detectors/src/loaders/drebin_loader.py --track 2 --method_name drebin
python main.py --clf_loader_path android-detectors/src/loaders/drebin_loader.py --track 3 --method_name drebin
```

If you use Docker:
```bash
docker build -t android android-detectors
docker run -itd --name android android
docker cp . android:/
docker exec -it android pip install -r /track_1/attack_requirements.txt
docker exec -it android pip install -r /track_2/attack_requirements.txt
docker exec -it android pip install -r /track_2/problem_space_attack/manipulation/Obfuscapk/src/requirements.txt
docker exec -it android python /main.py --clf_loader_path /android-detectors/src/loaders/drebin_loader.py --track 1 --method_name drebin
docker cp android:/submissions/submission_drebin_track_1.json submissions/
docker exec -it android python /main.py --clf_loader_path /android-detectors/src/loaders/drebin_loader.py --track 2 --method_name drebin
docker cp android:/submissions/submission_drebin_track_2.json submissions/
docker exec -it android python /main.py --clf_loader_path /android-detectors/src/loaders/drebin_loader.py --track 3 --method_name drebin
docker cp android:/submissions/submission_drebin_track_3.json submissions/
docker stop android
```

## Evaluation Metrics
- Detection Rate (a.k.a. True Positive Rate, Track 1 and 2): this metric is computed as the percentage of correctly detected malware and will be used for Track 1 and 2 on a test set containing only malware samples.
- False Positive Rate (Track 1 and 2): this metric is computed as the percentage of legitimate samples wrongly detected as malware and will be used for Track 1 and 2 on a test set containing only legitimate samples.
- F1 Score (Track 3): this metric is computed as the harmonic mean of Precision and Recall, and it is particularly suited for evaluating the binary classification performance on unbalanced datasets in a single metric.
- Area Under Time - AUT (Track 3): this metric was introduced in [4] to evaluate the performance of malware detectors over time. It is based on the trapezoidal rule as the AUC-based metrics. Its value is enclosed in the [0, 1] interval, where an ideal detector with robustness to temporal performance decay has AUT = 1. We compute the metric under point estimates of the F1 Score along the time period of the test samples.

## References

[1] Allix, K., Bissyandé, T.F., Klein, J., & Traon, Y.L. (2016). AndroZoo: Collecting Millions of Android Apps for the Research Community. 2016 IEEE/ACM 13th Working Conference on Mining Software Repositories (MSR), 468-471.

[2] https://www.virustotal.com

[3] Arp, D., Spreitzenbarth, M., Hubner, M., Gascon, H., & Rieck, K. (2014). DREBIN: Effective and Explainable Detection of Android Malware in Your Pocket. Network and Distributed System Security Symposium.

[4] Pendlebury, F., Pierazzi, F., Jordaney, R., Kinder, J., & Cavallaro, L. (2018). TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time. USENIX Security Symposium.