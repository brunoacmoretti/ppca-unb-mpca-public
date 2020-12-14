#!/usr/bin/python3

# Alunos: 
# - BRUNO APARECIDO CAPEL MORETTI (200080261)
# - JOSÉ NILO ALVES DE SOUSA NETO (200080351)
#
# PPCA/UnB - MPCA - Turma EB
# Data: 08 Dez 2020
"""
Algoritmos e Estrutura de Dados
Trabalho Final
"""

#%% Configuração inicial
import pandas as pd
import pylab as pl
import numpy as np
import scipy.optimize as opt

from sklearn import preprocessing
from sklearn.model_selection import train_test_split
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.datasets import fetch_openml
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import confusion_matrix
from sklearn.metrics import classification_report
from sklearn.metrics import roc_curve
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GridSearchCV

from matplotlib import pyplot
import matplotlib.pyplot as plt
import seaborn as sns

import time

start_time = time.time()

#%% Importação da base de dados

df_chunk_list = []

for df_chunk in pd.read_csv('./datasets/kddcup.data_corrected_2kk', header=None, iterator=True, chunksize=1000):
  df_chunk_list.append(df_chunk)

kddcyber_df = pd.concat(df_chunk_list)

kddcyber_df.head(10)
kddcyber_df.rename(columns={0:"duration", 1:"protocol_type", 2:"service", 3:"Flag", 4:"src_bytes", 5:"dest_bytes", 6:"Land", 7:"wrong_fragment", 8:"urgent", 9:"hot", 10:"num_failed_logins", 11:"logged_in", 12:"num_compromised", 13:"root_hell", 14:"su_attempted", 15:"num_root", 16:"num_file_creations", 17:"num_shells", 18:"num_acess_files", 19:"num_outbound_cmds", 20:"is_hot_login", 21:"is_guest_login", 22:"count", 23:"srv_count", 24:"serror_rate", 25:"srv_serror_rate", 26:"rerror_rate", 27:"srv_rerror_rate", 28:"same_srv_rate", 29:"diff_srv_rate", 30:"srv_diff_host_rate", 31:"dst_host_count", 32:"dst_host_srv_count", 33:"dst_host_same_srv_rate", 34:"same_srv_rate", 35:"dst_host_same_src_port_rate", 36:"dst_host_srv_diff_host_rate", 37:"dst_host_serror_rate", 38:"dst_host_srv_serror_rate", 39:"dst_host_rerror_rate", 40:"dst_host_rerror_rate", 41:"status"}, inplace=True)
kddcyber_df.head(10)

print("DataSet lido. Total de linhas: {}".format(len(kddcyber_df)))

# Criação da lista com instâncias binárias de tráfego de rede normal (0) e malicioso (1)
status_bin = []
# for i in range(0, len(kddcyber_df['status'])):
#   if kddcyber_df['status'][i]=="normal.":
#     status_bin.append(0)
#   else:
#     status_bin.append(1)

for i in kddcyber_df['status']:
  if i == "normal.":
    status_bin.append(0)
  else:
    status_bin.append(1)

print("status_bin: {}".format(len(status_bin)))

#%% Adição da lista ao data frame
kddcyber_df['status_bin'] = status_bin

#%% Checagem dos tipos de dados
print(kddcyber_df.dtypes)

#%% Criaçao das variáveis dummy
dummy_variable_1 = pd.get_dummies(kddcyber_df["protocol_type"])
print(dummy_variable_1.tail())

dummy_variable_2 = pd.get_dummies(kddcyber_df["service"])
print(dummy_variable_2.tail())

dummy_variable_3 = pd.get_dummies(kddcyber_df["Flag"])
print(dummy_variable_3.tail())

#%% Concatenação das variáveis dummy e dos dataframe
kddcyber_df = pd.concat([kddcyber_df, dummy_variable_1, dummy_variable_2, dummy_variable_3], axis=1)
print(kddcyber_df.head())

#%% Lista com os nomes das colunas
#colunas = list(kddcyber_df.columns.values.tolist())
#print(colunas)

#%% Separação em cojunto de treino e conjunto de teste
train, test = train_test_split(kddcyber_df, test_size=0.2, random_state=4,stratify=kddcyber_df['status_bin'])

#%% Separação dos conjuntos x e y de treino
x_train = np.asarray(train[["duration", "src_bytes", "dest_bytes", "Land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised", "root_hell", "su_attempted", "num_root", "num_file_creations", "num_shells", "num_acess_files", "num_outbound_cmds", "is_hot_login", "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "same_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_rerror_rate", 'icmp', 'tcp', 'udp', 'IRC', 'X11', 'Z39_50', 'auth', 'bgp', 'courier', 'csnet_ns', 'ctf', 'daytime', 'discard', 'domain', 'domain_u', 'echo', 'eco_i', 'ecr_i', 'efs', 'exec', 'finger', 'ftp', 'ftp_data', 'gopher', 'hostnames', 'http', 'http_443', 'imap4', 'iso_tsap', 'klogin', 'kshell', 'ldap', 'link', 'login', 'mtp', 'name', 'netbios_dgm', 'netbios_ns', 'netbios_ssn', 'netstat', 'nnsp', 'nntp', 'ntp_u', 'other', 'pm_dump', 'pop_2', 'pop_3', 'printer', 'private', 'red_i', 'remote_job', 'rje', 'shell', 'smtp', 'sql_net', 'ssh', 'sunrpc', 'supdup', 'systat', 'telnet', 'tftp_u', 'tim_i', 'time', 'urh_i', 'urp_i', 'uucp', 'uucp_path', 'vmnet', 'whois', 'OTH', 'REJ', 'RSTO', 'RSTOS0', 'RSTR', 'S0', 'S1', 'S2', 'S3', 'SF', 'SH']])
y_train = np.asarray(train['status_bin'])

#%% Separação dos conjuntos x e y de teste
x_test = np.asarray(test[["duration", "src_bytes", "dest_bytes", "Land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised", "root_hell", "su_attempted", "num_root", "num_file_creations", "num_shells", "num_acess_files", "num_outbound_cmds", "is_hot_login", "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "same_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_rerror_rate", 'icmp', 'tcp', 'udp', 'IRC', 'X11', 'Z39_50', 'auth', 'bgp', 'courier', 'csnet_ns', 'ctf', 'daytime', 'discard', 'domain', 'domain_u', 'echo', 'eco_i', 'ecr_i', 'efs', 'exec', 'finger', 'ftp', 'ftp_data', 'gopher', 'hostnames', 'http', 'http_443', 'imap4', 'iso_tsap', 'klogin', 'kshell', 'ldap', 'link', 'login', 'mtp', 'name', 'netbios_dgm', 'netbios_ns', 'netbios_ssn', 'netstat', 'nnsp', 'nntp', 'ntp_u', 'other', 'pm_dump', 'pop_2', 'pop_3', 'printer', 'private', 'red_i', 'remote_job', 'rje', 'shell', 'smtp', 'sql_net', 'ssh', 'sunrpc', 'supdup', 'systat', 'telnet', 'tftp_u', 'tim_i', 'time', 'urh_i', 'urp_i', 'uucp', 'uucp_path', 'vmnet', 'whois', 'OTH', 'REJ', 'RSTO', 'RSTOS0', 'RSTR', 'S0', 'S1', 'S2', 'S3', 'SF', 'SH']])
y_test = np.asarray(test['status_bin'])

#%% Modelagem da rede neural multicamada com a biblioteca scikit-learn
mlp = MLPClassifier(max_iter=1000, early_stopping=True,verbose=True, random_state=4, learning_rate_init=.001,validation_fraction=0.15,batch_size=10)

parameters = {
    'hidden_layer_sizes': [(1,), (3,), (6,), (3,3)],
    'activation': ['tanh', 'relu'],
    'solver': ['sgd', 'adam'],
    'alpha': [0.0001, 0.05],
    'learning_rate': ['constant', 'adaptative']
    }

clf = GridSearchCV(mlp, parameters, n_jobs=-1, cv=5)

#%% Treinamento da rede neural artificial
clf.fit(x_train, y_train)
print("Training set score: %f" % clf.score(x_train, y_train))

#%% Verificação dos melhores parâmetros
print('Best parameters found:\n', clf.best_params_)

#%% Aplicação do modelo ao conjunto de teste
y_test_calculado = clf.predict(x_test)
print(y_test_calculado)

#%% Probabilidades por classe
y_test_calc_prob = clf.predict_proba(x_test)
print(y_test_calc_prob)

#%% Avaliação do modelo desenvolvido
confusao = confusion_matrix(y_test, y_test_calculado)
print(confusao)

confusao_hat=pd.DataFrame(data=confusao, index=('normal=0','malicioso=1'),columns=('normal=0','malicioso=1'))
print(confusao_hat.head())

#%% Mapa de calor
sns.heatmap(confusao_hat,annot=True, cmap="YlGnBu")
plt.tight_layout()
plt.ylabel('Classe real')
plt.xlabel('Classe de predição')

#%% Métricas de classificação
print (classification_report(y_test, y_test_calculado))

end_time = time.time()
print("Início Término Tempo")
print("{} {} {}".format(start_time,end_time,end_time-start_time))

#%% Curva ROC
# Separação da probabilidade para a classe 1
yhat_prob = y_test_calc_prob[:, 1]

# Cálculo da curva
ns_fpr, ns_tpr, _ = roc_curve(y_test, yhat_prob)

# Plotagem da curva ROC
pyplot.plot(ns_fpr, ns_tpr, marker='.', label='Classificador MLP')

# Legendas dos Eixos
pyplot.xlabel('Taxa de Falsos Positivos')
pyplot.ylabel('Taxa de Verdadeiros Positivos')

# Plotagem das Legendas
pyplot.legend()

# Plotagem do gráfico
pyplot.show()

#%% Cálculo de AUC
lr_auc = roc_auc_score(y_test, yhat_prob)
print('ROC AUC=%.3f' % (lr_auc))

