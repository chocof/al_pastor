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
from sklearn.preprocessing import OneHotEncoder
from sklearn.utils.class_weight import compute_class_weight
from sklearn.utils import shuffle
tf.__version__

NOISE_CATEGORY = 5
NOISE_RATIO = 0.1
RANDOM_SEED = 42


class Dataset:
    def __init__(self, input, output):
        self.input = input
        self.output = output

    def get_input_dataset(self,):
        return self.input

    def get_output_dataset(self,):
        return self.output


class DL_Model:
    def __init__(self, csv_file):
        self.datasource = pd.read_csv(csv_file)
        self.train = None
        self.test = None

    def build_model(self):
        self._prepare_data()
        tf.random.set_seed(RANDOM_SEED)
        self.model = tf.keras.Sequential([
            tf.keras.layers.Dense(60, activation="relu"),
            tf.keras.layers.Dense(20, activation="relu"),
            tf.keras.layers.Dense(len(self.categories), activation="softmax"),
        ])

        # lr_scheduler = tf.keras.callbacks.LearningRateScheduler(lambda epoch: 1e-4 * 10 ** (epoch/20))
        self.model.compile(loss=tf.keras.losses.CategoricalCrossentropy(
        ), optimizer=tf.keras.optimizers.Adam(learning_rate=0.005), metrics=["accuracy"])

    def train_model(self,):
        val_cb = tf.keras.callbacks.EarlyStopping(
            monitor='val_accuracy', patience=20,
            mode='max', restore_best_weights=True
        )
        return self.model.fit(self.train.get_input_dataset(), self.train.get_output_dataset(
            ), epochs=40, batch_size=64, validation_split=0.4, callbacks=[val_cb], class_weight=self.cw_dict)

    def make_prediction(self, input):
        return self.model.predict(input)
    
    def evaluate(self,):
        prediction = self.make_prediction(self.test.get_input_dataset())
        y_pred = self.ohe.inverse_transform(prediction).flatten()
        y_true = self.ohe.inverse_transform(self.test.get_output_dataset()).flatten()
        cm = confusion_matrix(y_true, tf.round(y_pred))
        test_categories = np.unique(y_pred)
        disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["type:{}".format(x) for x in test_categories])
        disp.plot()
        plt.show()

    def _add_noise(self, input, output):
        # add random noise data to training
        noise_samples = math.floor(NOISE_RATIO*len(input))
        rdx_idx = np.random.randint(0, high=len(input), size=noise_samples)
        noise_input = []
        noise_output = []
        for i in rdx_idx:
            noise_input.append(np.random.random_sample((len(input[0]),)))
            noise_output.append(np.array([NOISE_CATEGORY]))
        self.ohe.fit(noise_output)
        noise_output = self.ohe.transform(noise_output)
        input = np.concatenate((input, np.array(noise_input)))
        output = np.concatenate((output, np.array(noise_output)))
        return shuffle(input, output)

    def _create_datasets(self, input, output):
        # split to testing and training datasets
        input_train, input_test, output_train, output_test = train_test_split(
            input, output, test_size=0.2, random_state=42)
        # Transform
        ct = make_column_transformer((MinMaxScaler(), self.headers))
        ct.fit(input_train)
        input_train_n = ct.transform(input_train)
        input_test_n = ct.transform(input_test)
        input_train_n, output_train = self._add_noise(
            input_train_n, output_train)
        input_test_n_wn, output_test_wn = self._add_noise(
            input_test_n, output_test)
        self.train = Dataset(input_train_n, output_train)
        self.test = Dataset(input_test_n_wn, output_test_wn)

    def _prepare_data(self,):
        # split to input output and get headers
        input, output = self.datasource.drop(
            ["severity"], axis=1), self.datasource["severity"].values.reshape(-1, 1)
        headers = list(input.columns.values)
        self.categories = np.insert(np.unique(output), 0, NOISE_CATEGORY)
        self.categories.sort()
        # one hot encode the output
        self.ohe = OneHotEncoder(
            categories=[self.categories], handle_unknown="ignore", sparse=False)
        self.ohe.fit(output)
        output_ohe = self.ohe.transform(output)
        # split and normalize datasets
        self._create_datasets(input, output_ohe)
        # now compute class weights
        df = pd.Series(np.array(
            [x[0] for x in self.ohe.inverse_transform(self.train.get_output_dataset())]))
        cw = compute_class_weight(
            classes=self.categories, y=df, class_weight="balanced")
        self.cw_dict = {idx: cw[idx] for idx in range(len(self.categories))}
