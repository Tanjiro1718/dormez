from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import numpy as np
import joblib
from PIL import Image
import os

def extract_features(image_path):
    img = Image.open(image_path).resize((64, 64)).convert('L')
    return np.array(img).flatten()

X, y = [], []
for label, folder in enumerate(['real', 'fake']):  # 0=real, 1=fake
    for fname in os.listdir(folder):
        X.append(extract_features(os.path.join(folder, fname)))
        y.append(label)
X = np.array(X)
y = np.array(y)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
clf = RandomForestClassifier()
clf.fit(X_train, y_train)
joblib.dump(clf, 'photo_verification_model.pkl')
print("Model trained and saved as photo_verification_model.pkl")