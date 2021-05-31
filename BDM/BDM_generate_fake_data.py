#!/bin/bash /usr/bin/python3
import csv, datetime
from faker import Faker

# Mostra mensagem no console
def Log(mensagem):
    print("[{}] {}".format(datetime.datetime.now(), mensagem))

# Salvar arquivos no disco
def SalvarArquivo(nome_arquivo, dados):
    Log("Salvando arquivo '{}' com {} registros.".format(nome_arquivo, len(dados)-1))
    with open(nome_arquivo, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(dados)

# Definição da instância Faker com dados em PT_BR
fake = Faker(["pt_BR"])

# Listas para armazenamento dos dados falsos
leak_pessoas = [["cpf", "nome", "tipo_sanguineo", "dt_nascimento", "rg", "email", "telefone"]]
leak_credenciais_plaintext = [["email", "usuario", "senha"]]
leak_credenciais_hash = [["email", "username", "password", "hash_type"]]

# Total de registros falsos que serão gerados
total_registros = 1000000

Log("Gerando {} registros com dados falsos.".format(total_registros))

# Geração dos dados falsos
for i in range(total_registros):
    p = fake.profile(fields=["mail", "username", "blood_group"])
    email = p["mail"]
    usuario = p["username"]
    tiposanguineo = p["blood_group"]
    nome = "{} {}".format(fake.first_name(), fake.last_name())
    cpf = fake.ssn()
    rg = fake.rg()
    telefone = fake.msisdn()
    data_nascimento = fake.date_between(start_date='-70y', end_date='-12y')

    leak_pessoas.append([cpf, nome, tiposanguineo, data_nascimento, rg, email, telefone])

    if i % 2 == 0:
        leak_credenciais_plaintext.append([email, usuario, fake.password()])

    if i % 3 == 0:
        leak_credenciais_hash.append([email, usuario, fake.md5(), "MD5"])
    
    if i % 5 == 0:
        leak_credenciais_hash.append([email, usuario, fake.sha1(), "SHA1"])
    
    if i % 10 == 0:
        leak_credenciais_hash.append([email, usuario, fake.sha256(), "SHA256"])
    
Log("{} registros com dados falsos gerados.".format(total_registros))

# Escrever arquivos em disco
SalvarArquivo('leak_dados_pessoas.csv', leak_pessoas)
SalvarArquivo('leak_credenciais_plaintext.csv', leak_credenciais_plaintext)
SalvarArquivo('leak_credenciais_hash.csv', leak_credenciais_hash)
