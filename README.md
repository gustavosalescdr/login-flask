Sistema de Login com Flask

Esse projeto é um sistema simples de autenticação de usuários que desenvolvi para praticar back-end com Python e Flask.

A ideia foi entender na prática como funciona:

Cadastro de usuários

Login e logout

Criptografia de senhas

Sessão de usuário

Validação de formulários

Tecnologias usadas

Python

Flask

SQLite

HTML / CSS

Funcionalidades

O sistema permite:

Criar conta com nome, e-mail e senha

Fazer login com validação de dados

Manter o usuário logado usando sessão

Senhas armazenadas de forma segura (hash)

Como rodar o projeto

Clone o repositório:

git clone https://github.com/gustavosalescdr/login-flask
cd login-flask


Crie um ambiente virtual e instale as dependências:

python -m venv venv
venv\Scripts\activate   # Windows
pip install -r requirements.txt


Rode o projeto:

python app.py


A aplicação estará disponível em:
http://127.0.0.1:5000

Versão online

O projeto também está publicado na nuvem:

👉 https://login-flask-7838.onrender.com

Objetivo do projeto

Esse projeto faz parte dos meus estudos para entrar na área de desenvolvimento back-end.
Foi focado em entender autenticação de usuários e estrutura básica de uma aplicação web com Flask.
