### Track 3: Temporal Robustness to Data Drift - Submission example

Download all the datasets and pre-computed features from the [ELSA benchmarks website](https://benchmarks.elsa-ai.eu/?ch=6&com=downloads) inside the `data` directory.

Pre-trained models can also be downloaded from Drive:
- [DREBIN](https://drive.google.com/drive/folders/118Eb_KoW6vE38aqDY0MmVfHUtLOwO8Vk?usp=sharing)
- [SecSVM](https://drive.google.com/drive/folders/1pSO0UWvBJsrkIgshYkHwR3OqR_slZGBH?usp=sharing)

The downloaded files must be placed in the `android-detectors/pretrained` folder.

If you want to use Docker, you can use the following commands (from the repository root directory):
```bash
docker build -t android android-detectors
docker run -itd --name android android
docker cp data android:/
docker cp track_3/drebin_track_3.py android:/android-detectors/
docker exec android mkdir /android-detectors/submissions
docker exec -it android python /android-detectors/drebin_track_3.py
docker stop android
```
The submission file and the pretrained model files can be gathered from the container:
```bash
docker cp android:/android-detectors/submissions/submission_drebin_track_3.json track_3/submissions/
docker cp android:/android-detectors/pretrained/drebin_classifier.pkl android-detectors/pretrained/
docker cp android:/android-detectors/pretrained/drebin_vectorizer.pkl android-detectors/pretrained/
```

If you don't want to use Docker, it is recommended to create a new environment, for instance if you use conda you can run (it might be required to append `android-detectors/src` directory to the python path before launching the script):
```bash
conda create -n android python=3.9
conda activate android
pip install -r ./requirements.txt
export PYTHONPATH="${PYTHONPATH}:android-detectors/src"
python3 track_3/drebin_track_3.py
```