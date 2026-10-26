# Secure Password Manager (ManageMyShit)

Um gerenciador de senhas de linha de comando (CLI) desenvolvido em Python, focado em segurança, criptografia robusta e armazenamento local seguro. O projeto foi construído utilizando conceitos modernos de criptografia e derivação de chaves para proteger dados sensíveis.

---

## 🚀 Funcionalidades

- **Criptografia Simétrica Avançada:** Utiliza o algoritmo **Fernet** (baseado em AES) para garantir a confidencialidade das senhas armazenadas.
- **Derivação de Chave Segura:** Emprega **PBKDF2HMAC** com **SHA-256** e `100.000 iterações`, combinado com um **Salt** exclusivo gerado aleatoriamente (`os.urandom`), dificultando ataques de força bruta e *rainbow tables*.
- **Banco de Dados Local:** Armazenamento estruturado e leve utilizando **SQLite**.
- **Gerador de Senhas Automáticas:** Cria senhas fortes contendo letras maiúsculas, minúsculas, números e caracteres especiais.
- **Integração com Área de Transferência:** Permite copiar senhas diretamente para o *clipboard* de forma prática com a biblioteca `pyperclip`.
- **Proteção de Entrada:** Uso da biblioteca `getpass` para ocultar a digitação de senhas e da senha mestre no terminal.

---

## 🛠️ Tecnologias e Bibliotecas Utilizadas

- **Python 3.x**
- [`cryptography`](https://cryptography.io/): Para operações criptográficas e chaves seguras.
- [`sqlite3`](https://docs.python.org/3/library/sqlite3.html): Para gerenciamento do banco de dados relacional local.
- [`pyperclip`](https://pypi.org/project/pyperclip/): Para manipulação da área de transferência.

---

## 📦 Como Instalar e Executar

### 1. Pré-requisitos
Certifique-se de ter o **Python** instalado em sua máquina.

### 2. Clonar o repositório
```bash
git clone https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git
cd ManageMyShit