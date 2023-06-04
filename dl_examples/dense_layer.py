import tensorflow as tf
from tensorflow.keras.utils import plot_model
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import math
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler, OneHotEncoder
from sklearn.compose import make_column_transformer
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
from google.colab import drive    
from sklearn.preprocessing import OneHotEncoder
from sklearn.utils.class_weight import compute_class_weight
from sklearn.utils import shuffle
tf.__version__

NOISE_CATEGORY = 5
NOISE_RATIO = 0.2

# add the produced csv file here
csv_file = "input.csv"
dataset=pd.read_csv(csv_file)

input, output = dataset.drop(["severity", "threat_class", "threat_msg"], axis=1), dataset["severity"].values.reshape(-1,1)
headers = list(input.columns.values)

categories = np.insert(np.unique(output), 0, NOISE_CATEGORY)
categories.sort()

ohe = OneHotEncoder(categories=[categories], handle_unknown="ignore", sparse=False)
ohe.fit(output)
output_ohe = ohe.transform(output)

str_headers = []#["Proto", "State", "Flgs", "TcpOpt",]
non_str_headers = [hdr for hdr in headers if hdr not in str_headers]

ct = make_column_transformer(
    (OneHotEncoder(handle_unknown="ignore"), str_headers),
    (MinMaxScaler(), non_str_headers),
)
ct.fit(input)
input_train, input_test, output_train, output_test = train_test_split(input, output_ohe, test_size=0.2, random_state=42)

input_train_n = ct.transform(input_train)
input_test_n = ct.transform(input_test)

def add_noise(input, output):
  # add random noise data to training
  noise_samples = math.floor(NOISE_RATIO*len(input))
  rdx_idx = np.random.randint(0, high=len(input), size=noise_samples)
  noise_input = []
  noise_output = []
  for i in rdx_idx:
    noise_input.append(np.random.random_sample((len(input[0]),)))
    noise_output.append(np.array([NOISE_CATEGORY]))
  ohe.fit(noise_output)
  noise_output = ohe.transform(noise_output)
  input = np.concatenate((input, np.array(noise_input)))
  output = np.concatenate((output, np.array(noise_output)))
  return shuffle(input, output)

input_train_n, output_train = add_noise(input_train_n, output_train)
input_test_n, output_test = add_noise(input_test_n, output_test)
df = pd.Series(np.array([x[0] for x in ohe.inverse_transform(output_train)]))

cw = compute_class_weight(classes=categories , y=df, class_weight="balanced")
cwd = { idx: cw[idx] for idx in range(len(categories))}
tf.random.set_seed(42)

nof_layers = 7
nof_nodes = 60
layers = [tf.keras.layers.Dense(nof_nodes, activation="relu") for x in range(0, nof_layers)]
model = tf.keras.Sequential([
  *layers,
  tf.keras.layers.Dense(len(categories), activation="softmax"),
])

val_cb = tf.keras.callbacks.EarlyStopping(
    monitor='val_accuracy', patience=20,
    mode='max', restore_best_weights=True
)
# lr_scheduler = tf.keras.callbacks.LearningRateScheduler(lambda epoch: 1e-4 * 10 ** (epoch/10))
model.compile(loss = tf.keras.losses.CategoricalCrossentropy(), optimizer=tf.keras.optimizers.Adam(learning_rate=0.0016), metrics=["accuracy"])
model.fit(input_train_n, output_train, epochs=40, batch_size=64, validation_split=0.4, callbacks=[ val_cb ], class_weight=cwd)

prediction = model.predict(input_test_n)
y_pred = ohe.inverse_transform(prediction).flatten()
y_true = ohe.inverse_transform(output_test).flatten()

cm = confusion_matrix(y_true, tf.round(y_pred))
test_categories = np.unique(y_pred)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["type:{}".format(x) for x in categories])
disp.plot()
plt.show()