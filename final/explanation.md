# Documentation

## Overview
We implemented a machine learning approach to identify video streaming services based on network SYN packets. The analysis processes PCAP files and builds a Random Forest classifier to distinguish between different streaming services.

## Data Preparation

### Package Imports
First, we import the necessary Python packages:

```python
import os
import pandas as pd
from tqdm import tqdm
import numpy as np
from scapy.all import rdpcap, TCP, IP
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import RandomizedSearchCV
from scipy.stats import randint, uniform


```

### Loading and Processing Data
The data consists of PCAP files; each file is named with a format that includes its ID and streaming service label. We are only using a subset of the available data, due to kernel crashes when we tried using the entire dataset. We start by creating a dataframe that maps file paths to their labels:

```python
pcap_dir = 'output_dir/'
NUM_FILES = 1000

pcap_files = [f for f in os.listdir(pcap_dir) if f.endswith('.pcap')]

sample_ids = []
labels = []

for file in pcap_files:
    parts = file.split('_')
    sample_id = parts[0]
    label = parts[1].replace('.pcap', '')
    sample_ids.append(sample_id)
    labels.append(label)

data = pd.DataFrame({
    'sampleID': sample_ids,
    'label': labels,
    'filepath': [os.path.join(pcap_dir, f) for f in pcap_files]
})
```

## Feature Extraction

### SYN Packet Analysis
We extract features from the first 10 SYN packets. The features include:
- packet length
- source port
- destination port
- packet timing
- inter-arrival times

```python
def extract_features(pcap_file):
    packets = rdpcap(pcap_file)
    syn_packets = []
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            tcp_layer = pkt[TCP]
            if tcp_layer.flags & 0x02:
                syn_packets.append(pkt)
                if len(syn_packets) == 10:
                    break

    features = {}
    for i, pkt in enumerate(syn_packets, 1):
        features[f'syn_{i}_pkt_len'] = len(pkt)
        features[f'syn_{i}_src_port'] = pkt[TCP].sport
        features[f'syn_{i}_dst_port'] = pkt[TCP].dport
        features[f'syn_{i}_time'] = pkt.time

    times = [pkt.time for pkt in syn_packets]
    inter_arrival_times = np.diff(times)
    for i, inter_time in enumerate(inter_arrival_times, 1):
        features[f'syn_{i}_inter_arrival'] = inter_time

    return features
```

## Data Processing

### Feature Scaling
We standardize the features using StandardScaler to ensure all features contribute equally:

```python
exclude_columns = ['sampleID', 'label', 'label_encoded', 'filepath']
feature_columns = [col for col in data_features.columns if col not in exclude_columns]

scaler = StandardScaler()
data_features[feature_columns] = scaler.fit_transform(data_features[feature_columns])
```

### Train-Test Split
The data is split into training and testing sets, with stratification to maintain class distribution:

```python
TEST_SIZE = 0.2 
RANDOM_STATE = 42

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=y
)
```

## Model Training

### Random Forest Classifier
We implemented a Random Forest classifier, because of its robustness and versatility.

```python
rf_classifier = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight='balanced',
    n_jobs=-1
)

rf_classifier.fit(X_train, y_train)

y_pred = rf_classifier.predict(X_test)
```

We did hyperparameter tuning:

```python
param_dist = {
    'n_estimators': randint(100, 300),
    'max_depth': [None, 10, 20],
    'min_samples_split': randint(2, 11),
    'min_samples_leaf': randint(1, 5),
    'bootstrap': [True, False],
    'class_weight': ['balanced', None]
}

rf = RandomForestClassifier(random_state=42, n_jobs=-1)

random_search = RandomizedSearchCV(
    estimator=rf,
    param_distributions=param_dist,
    n_iter=50,
    cv=5,
    scoring='balanced_accuracy',
    random_state=42,
    n_jobs=-1,
    verbose=2,
    return_train_score=True
)

random_search.fit(X_train, y_train)
```

## Results
Cross-Validation Balanced Accuracy: 0.7303

Balanced Accuracy with the best model: 0.7669

```      
              precision    recall  f1-score   support

      amazon       0.70      0.78      0.74        18
     netflix       0.75      0.56      0.64        59
      twitch       0.81      0.81      0.81        31
     youtube       0.81      0.92      0.86        92
    accuracy                           0.79       200
   macro avg       0.77      0.77      0.76       200
weighted avg       0.78      0.79      0.78       200
```

The model achieves solid performance in distinguishing between different streaming services, with a balanced accuracy of 76.69. 

Our implementation shows the feasibility of early traffic classification for streaming services using only the first 10 SYN packets.