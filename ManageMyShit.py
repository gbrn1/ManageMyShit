# ManageMyShit.py 
# Programa de gerenciamento de senhas com criptografia e armazenamento seguro em banco de dados SQLite.

import base64
import hashlib
import os
import sqlite3
import getpass
import pyperclip
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


def cadastroChave(senha_mestre):
    with open('master.key', 'wb') as master:
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        )
        chave_bytes = kdf.derive(senha_mestre.encode())
        chave_criptografia_fernet = base64.urlsafe_b64encode(chave_bytes)  
        hash_verificacao_banco = hashlib.sha256(chave_bytes).hexdigest()
        writekey = salt.hex() + ':' + hash_verificacao_banco
        master.write(writekey.encode())

def verificaSenhaMestre():
    if not os.path.exists('master.key'):
        print("Nenhuma senha mestre cadastrada. Por favor, cadastre uma senha mestre primeiro.")
        return False

    with open('master.key', 'rb') as master:
        writekey = master.read().decode()
        salt_hex, hash_verificacao_banco = writekey.split(':')
        salt = bytes.fromhex(salt_hex)

    senha_mestre = getpass.getpass("Digite sua senha mestre: ")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    chave_bytes = kdf.derive(senha_mestre.encode())
    hash_verificacao_input = hashlib.sha256(chave_bytes).hexdigest()

    if hash_verificacao_input == hash_verificacao_banco:
        print("Senha mestre verificada com sucesso!")
        return True
    else:
        print("Senha mestre incorreta.")
        return False

def criar_banco():
    conn = sqlite3.connect('senhas.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS senhas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            usuario TEXT NOT NULL,
            senha TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def adicionar_senha():
    if not verificaSenhaMestre():
        return

    nome = input("Digite o nome do serviço: ")
    usuario = input("Digite o nome de usuário: ")
    tipo_de_senha = input("Deseja gerar uma senha segura automaticamente? (s/n): ")
    if tipo_de_senha.lower() == 's':
        senha = gerar_senha()
        print(f"Senha gerada: {senha}")
    else:
        senha = getpass.getpass("Digite a senha: ")

    with open('master.key', 'rb') as master:
        writekey = master.read().decode()
        salt_hex, hash_verificacao_banco = writekey.split(':')
        salt = bytes.fromhex(salt_hex)

    senha_mestre = getpass.getpass("Digite sua senha mestre novamente para criptografar a senha: ")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    chave_bytes = kdf.derive(senha_mestre.encode())
    chave_criptografia_fernet = base64.urlsafe_b64encode(chave_bytes)
    fernet = Fernet(chave_criptografia_fernet)
    senha_criptografada = fernet.encrypt(senha.encode()).decode()

    conn = sqlite3.connect('senhas.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO senhas (nome, usuario, senha) VALUES (?, ?, ?)
    ''', (nome, usuario, senha_criptografada))
    conn.commit()
    conn.close()
    print("Senha adicionada com sucesso!")

def listar_senhas():
    if not verificaSenhaMestre():
        return

    conn = sqlite3.connect('senhas.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, nome, usuario, senha FROM senhas')
    senhas = cursor.fetchall()
    conn.close()

    if not senhas:
        print("Nenhuma senha cadastrada.")
        return

    with open('master.key', 'rb') as master:
        writekey = master.read().decode()
        salt_hex, hash_verificacao_banco = writekey.split(':')
        salt = bytes.fromhex(salt_hex)

    senha_mestre = getpass.getpass("Digite sua senha mestre novamente para descriptografar as senhas: ")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    chave_bytes = kdf.derive(senha_mestre.encode())
    chave_criptografia_fernet = base64.urlsafe_b64encode(chave_bytes)
    fernet = Fernet(chave_criptografia_fernet)

    print("\nSenhas cadastradas:")
    for id, nome, usuario, senha_criptografada in senhas:
        try:
            senha_descriptografada = fernet.decrypt(senha_criptografada.encode()).decode()
            print(f"ID: {id}, Serviço: {nome}, Usuário: {usuario}, Senha: {senha_descriptografada}")
        except Exception as e:
            print(f"Erro ao descriptografar a senha para o serviço '{nome}': {e}")
    try:
        selecao = int(input("Selecione uma senha pelo ID para copiar para a área de transferência ou pressione Enter para voltar ao menu: "))
        if selecao:
            selecao_id = int(selecao)
            senha_selecionada = next((senha for senha in senhas if senha[0] == selecao_id), None)
            if senha_selecionada:
                senha_criptografada = senha_selecionada[3]
                senha_descriptografada = fernet.decrypt(senha_criptografada.encode()).decode()
                pyperclip.copy(senha_descriptografada)
                print(f"Senha para o serviço '{senha_selecionada[1]}' copiada para a área de transferência.")
            else:
                print("ID inválido. Voltando ao menu.")
    except ValueError:
        print("Nenhuma senha copiada. Voltando ao menu.")

def gerar_senha(tamanho=12):
    import random
    import string

    caracteres = string.ascii_letters + string.digits + string.punctuation
    senha_gerada = ''.join(random.choice(caracteres) for _ in range(tamanho))
    return senha_gerada

def altera_senha():
    conn = sqlite3.connect('senhas.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, nome, usuario, senha FROM senhas')
    senhas = cursor.fetchall()
    conn.close()
    if not senhas:
        print("Nenhuma senha cadastrada.")
        return

    with open('master.key', 'rb') as master:
        writekey = master.read().decode()
        salt_hex, hash_verificacao_banco = writekey.split(':')
        salt = bytes.fromhex(salt_hex)

    senha_mestre = getpass.getpass("Digite sua senha mestre novamente para descriptografar as senhas: ")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    chave_bytes = kdf.derive(senha_mestre.encode())
    chave_criptografia_fernet = base64.urlsafe_b64encode(chave_bytes)
    fernet = Fernet(chave_criptografia_fernet)

    print("\nSenhas cadastradas:")
    for id, nome, usuario, senha_criptografada in senhas:
        try:
            senha_descriptografada = fernet.decrypt(senha_criptografada.encode()).decode()
            print(f"ID: {id}, Serviço: {nome}, Usuário: {usuario}, Senha: {senha_descriptografada}")
        except Exception as e:
            print(f"Erro ao descriptografar a senha para o serviço '{nome}': {e}")
    try:
        selecao = int(input("Selecione uma senha pelo ID para alterar ou excluir: "))
        senha_selecionada = next((senha for senha in senhas if senha[0] == selecao), None)
        if senha_selecionada:
            acao = input("Deseja alterar (a) ou excluir (e) a senha? (a/e): ")
            if acao.lower() == 'a':
                nova_senha = getpass.getpass("Digite a nova senha: ")
                senha_criptografada = fernet.encrypt(nova_senha.encode()).decode()
                conn = sqlite3.connect('senhas.db')
                cursor = conn.cursor()
                cursor.execute('UPDATE senhas SET senha = ? WHERE id = ?', (senha_criptografada, selecao))
                conn.commit()
                conn.close()
                print("Senha alterada com sucesso!")
            elif acao.lower() == 'e':
                confirma_exclusao = input(f"Tem certeza que deseja excluir a senha para o serviço '{senha_selecionada[1]}'? (s/n): ")
                if confirma_exclusao.lower() == 's':
                    conn = sqlite3.connect('senhas.db')
                    cursor = conn.cursor()
                    cursor.execute('DELETE FROM senhas WHERE id = ?', (selecao,))
                    conn.commit()
                    conn.close()
                    print("Senha excluída com sucesso!")
                else:
                    print("Exclusão cancelada.")
            else:
                print("Ação inválida. Voltando ao menu.")
        else:
            print("ID inválido. Voltando ao menu.")
    except ValueError:
        print("Nenhuma ação realizada. Voltando ao menu.")

def menu():
    while True:

        print("\nMenu:")
        print("1. Adicionar senha")
        print("2. Listar senhas")
        print("3. Gerar senha segura")
        print("4. Alterar ou excluir senha")
        print("5. Sair")
        escolha = input("Escolha uma opção: ")

        if escolha == '1':
            adicionar_senha()
        elif escolha == '2':
            listar_senhas()
        elif escolha == '3':
            senha_gerada = gerar_senha()
            print(f"Senha gerada: {senha_gerada}")
            pyperclip.copy(senha_gerada)
            print("Senha copiada para a área de transferência.")
        elif escolha == '4':
            altera_senha()
        elif escolha == '5':
            print("Saindo do gerenciador de senhas.")
            break
        else:
            print("Opção inválida. Por favor, tente novamente.")


def main():
    print("Bem-vindo ao gerenciador de senhas!")
    if not os.path.exists('senhas.db'):
        confirma = input("Nenhum banco de dados encontrado. Deseja criar um novo banco de dados? (s/n): ")
        if confirma.lower() != 's':
            print("Operação cancelada. Saindo do programa.")
            return
        else:
            criar_banco()
            print("Banco de dados criado com sucesso!")
    if not os.path.exists('master.key'):
        print("Vamos começar cadastrando sua senha mestre.")
        senha_mestre = getpass.getpass("Cadastre sua senha mestre: ")
        confirma_senha = getpass.getpass("Confirme sua senha mestre: ")
        if senha_mestre != confirma_senha:
            print("As senhas não coincidem. Por favor, tente novamente.")
            return
        else:
            cadastroChave(senha_mestre)
            print("Senha mestre cadastrada com sucesso!")
    menu()

main()