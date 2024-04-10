# elsa-cybersecurity
Official repository for the [Cybersecurity use case](https://benchmarks.elsa-ai.eu/?ch=6) of [ELSA](https://www.elsa-ai.eu/) EU Project.

## Overview

The Cybersecurity use case aims to evaluate machine learning methods when they are used as a first line of defense against malicious software (malware). The considered use cases focused on detecting malware for the Android Operating System. On this task, machine learning usually performs well, learning common patterns from data and enabling the detection of potentially never-before-seen malware samples. However, it has been shown that those detectors (i) tend to exhibit a rapid performance decay over time due to the natural evolution of samples and (ii) can be bypassed by slightly manipulating malware samples in an adversarial manner. The practical impact of these two issues is that current learning-based malware detectors need constant updates and retraining on newly collected and labeled data.

We propose a threefold benchmark to provide tools for comparing AI-based Android malware detectors in a realistic setting. They challenge the research community to go beyond simplistic assumptions to ultimately design more robust AI models that can be maintained and updated more efficiently, saving human labor and effort. The competition is deployed in periodical evaluation rounds and is structured in three separate tracks:

### Track 1 - Adversarial Robustness to Feature-space Attacks
In this scenario, we aim to measure how much the models' predictions change against increasing amounts of adversarial manipulations, assuming the attacker knows the features used and the model itself and has unrestricted access to it. A feature-space evasion attack will be performed on test applications, perturbing the feature vector with constraints to ensure that applying these manipulations to an APK preserves its malicious functionalities. The applied perturbation is bounded based on the number of modified features.

### Track 2: Adversarial Robustness to Problem-space Attacks
The problem-space attack scenario consists of manipulating the APK files directly rather than only simulating the effect of the attack at the feature level. In this case, we assume the attacker does not know the target model and its features. An input-space evasion attack will be performed on the test applications, applying functionality-preserving manipulation to the APKs. The applied manipulations are bounded based on the size of the injected data.

### Track 3: Temporal Robustness to Data Drift
In this setting, we will collect the performance evaluation of the given AI-based detectors with respect to (future) data collected over time, updating the test applications with new samples in each evaluation round.

## Participation Instructions

### General rules
1. The binary classification task consists of distinguishing malware samples from benign applications that rely only on ML-based approaches. The use of whitelisting, blacklisting, or signatures is not allowed. The submitted models can only rely on statically extracted features, i.e., applications must not be executed during the feature extraction process.
2. Participants must train their models only on the provided training dataset. They must evaluate them on the provided test datasets employing the provided evaluation code.
3. Everything must be fully reproducible. The participants must provide all the required code to train and deploy their models, including the feature extraction process (except for Track 1, where the features will be provided to the participants) and, if necessary, the pre-set random seeds to guarantee more accurate reproducibility. All submitted models and results are subject to re-evaluations. We ask that pre-trained models and source code be publicly released (e.g., on a GitHub repository). 
4. To participate in a track by submitting a new model, users must train the model and follow the track instructions to understand how to compute the predicted labels and scores on the released test datasets. The models must be evaluated on all the provided test sets.

### Track 1 - Adversarial Robustness to Feature-space Attacks
1. The submitted models must only rely on the provided feature set or a custom subset thereof (in this case, the user must specify the selected features). 
2. The submitted models must accept feature vectors as input and provide the classification score of the positive class and the predicted class labels as output. 
3. The submitted models must have a False Positive Rate equal to or lower than 1% on the provided validation set composed of benign samples only. 
4. The testing must be performed with the provided code, which will classify the test sets, execute a feature-space attack, and output the submission file with predicted labels and scores.

Submission examples can be found [here](https://github.com/pralab/elsa-cybersecurity/blob/main/track_1/README.md).

### Track 2: Adversarial Robustness to Problem-space Attacks (starting soon)
1. The submitted models must accept APK files as input and provide the classification scores of the positive class and the predicted class labels as output. 
2. The submitted models must have a False Positive Rate equal to or lower than 1% on the provided validation set composed of benign samples only. 
3. The testing must be performed with the provided code, which will classify the test sets, execute a problem-space attack, and output the submission file with predicted labels and scores.

### Track 3: Temporal Robustness to Data Drift
1. The submitted models must accept APK files as input and provide the classification scores of the positive class and the predicted class labels as output. 
2. To perform the testing, the participants must classify the test applications with their model and provide the predicted labels and the classification scores of the positive class.

Submission examples can be found [here](https://github.com/pralab/elsa-cybersecurity/blob/main/track_3/README.md).

### Data
All the datasets and pre-computed features can be downloaded [here](https://benchmarks.elsa-ai.eu/?ch=6&com=downloads) (registration is required).


### Model implementation instructions
In [this repository](https://github.com/pralab/android-detectors) you can find already implemented models which serve as baselines for the benchmarks hosted in the Cybersecurity Use Case.
Please, follow these instructions when implementing your model:
- The model class must necessarily expose a small set of methods. All the details can be found in the [BaseModel](https://github.com/pralab/android-detectors/src/base/base_model.py) class. We suggest to extend this class.
- To ensure reproducibility and allow validating the results, make sure to set all random seeds, add all the requirements, and if necessary a Dockerfile from where to run the evaluation scripts.
- Provide one or more scripts for model training and evaluation (including the submission file creation).

### Submission file format
For all the evaluation tracks, the submission must be uploaded in a JSON file, containing a list with a dictionary for each required evaluation. The keys of each dictionary are the SHA256 hashes of the test set samples for the respective dataset. An array containing the predicted class label (either 0 or 1) and the positive class score must be associated with each SHA256 hash. For Tracks 1 and 2, the first dictionary contains the classification results on the provided goodware-only test set (with which to check the false positive rate), while the other ones contain the classification results on the provided malware-only test set with different amounts of adversarial perturbations. For track 3, each dictionary corresponds to an evaluation round test set (the order must be preserved).
```
[
  {
    sha256: [label, score],
    …
  },
  …
]
```