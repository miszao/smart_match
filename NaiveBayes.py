import pandas as pd
from sklearn.utils import shuffle
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score


class NaiveBayes():
    def __init__(self, *args, **kwargs):
        super(NaiveBayes, self).__init__(*args, **kwargs)

    def init_classifier(self):
        """
        This function:
        1. imports data from *.csv file and splits it to train and test batches;
        2. drops IP columns as they are not used as features;
        3. splits labels from pandas dataframe;
        4. encodes the labels;
        5. scales the data and uses it to train the Naive Bayes classifier object
        Long story short, it initializes Naive Bayes object and prepares it for traffic recognition
        """
        self.dataframe = pd.read_csv('dataset1.csv')
        self.dataframe.drop(['ip_src', 'ip_dst'], axis=1, inplace=True)
        self.dataframe = shuffle(self.dataframe)
        self.labels = self.dataframe.pop('tag')
        self.le = LabelEncoder()
        self.labels = self.le.fit_transform(self.labels)
        self.x_train, self.x_test, self.y_train, self.y_test = train_test_split(self.dataframe, self.labels,
                                                                                test_size=0.3,
                                                                                random_state=31)
        self.stdsc = StandardScaler()
        self.x_train_std = self.stdsc.fit_transform(self.x_train)
        self.x_test_std = self.stdsc.transform(self.x_test)
        self.classifier = GaussianNB()
        self.classifier.fit(self.x_train_std, self.y_train)
        GaussianNB(priors=None)
        self.y_pred = self.classifier.predict(self.x_test_std)
        self.readable_labels = self.le.inverse_transform(self.labels)

    def get_accuracy_score(self):
        return accuracy_score(y_true=self.y_test, y_pred=self.y_pred)

    def get_label_encoding(self):
        return dict(zip(self.labels, self.readable_labels))

    def inspect_flow(self, flow_container={}):
        flow_data = {'ip_proto': flow_container['ip_proto_list'],
                     'port_src': flow_container['src_port_list'],
                     'port_dsc': flow_container['dst_port_list'],
                     'avg_pkt_size': flow_container['avg_pkt_size_list']}
        flow_dataframe = pd.DataFrame(flow_data)
        flow_dataframe_std = self.stdsc.transform(flow_dataframe)
        labels = self.classifier.predict(flow_dataframe_std)
        return labels
