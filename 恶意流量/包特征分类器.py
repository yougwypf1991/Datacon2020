from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn import metrics
import matplotlib.pyplot as plt
import numpy as np
import globalValue
import pandas as pd


def RandomForestClassfy(X, Y):  #分类决策
    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2)
    rfc = RandomForestClassifier(n_estimators=7, n_jobs=-1, max_features="auto", random_state=11, bootstrap=True)
    score = cross_val_score(rfc, X_train, Y_train)
    print('交叉验证准确度：', str(score.mean()))
    rfc.fit(X_train, Y_train)

    predict_res = []
    # for i in len(X_test):
    results = rfc.predict(X_test)
    tmp = 0
    count = 0
    for res in results:
        if res == Y_test.iloc[count]:
            tmp += 1
        count += 1
    print('预测准确度为：', tmp/len(results))






def main():
    path = globalValue.global_feature_file
    data = pd.read_csv(path, header=None)
    # print(data)
    X_data = data.loc[:, 2:]
    # print(X_data)
    Y_data = data.loc[:, 1]
    # print(Y_data)
    RandomForestClassfy(X_data, Y_data)

if __name__ == '__main__':
    main()