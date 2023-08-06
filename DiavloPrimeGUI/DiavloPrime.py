import os
import json
import hashlib
import requests
import tkinter as tk
from tkinter import messagebox, ttk
from colorama import Fore, init

init()

ascii_art = """
____   ____ _______ 
|  _ \ / __ \__   __|
| |D | | |  | | |   
| |P | | |  | | |   
| |R | | |__| | | |
|_|I |  \____/  |_|   
  M E 
"""

print(Fore.GREEN + ascii_art + Fore.RESET)

dbs = os.listdir("dbs")
allData = []

def bruteforce(hash, salt):
    if len(hash) == 64:
        for password in words:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if password_hash == hash:
                return password
    elif len(hash) == 86 or len(hash) == 85:
        parts = hash.split("$")
        salt1 = parts[2]
        hash1 = parts[3]
        for word in words:
            var2 = hashlib.sha256(word.encode()).hexdigest()
            final = hashlib.sha256((var2 + salt1).encode()).hexdigest()
            if final == hash1:
                return word
    elif len(hash) == 128:
        for word in words:
            var2 = hashlib.sha512(word.encode()).hexdigest()
            final = hashlib.sha512((var2 + salt).encode()).hexdigest()
            if final == hash:
                return word
    elif "SHA256" in hash:
        parts = hash.split("$")
        salt = parts[1]
        wow = parts[2]
        for word in words:
            word_hash = hashlib.sha256(hashlib.sha256(word.encode()).hexdigest().encode() + salt.encode()).hexdigest()
            if word_hash == wow:
                return word
    elif "SHA512" in hash:
        parts = hash.split("$")
        salt = parts[1]
        wow = parts[2]
        for word in words:
            passenc = hashlib.sha512(word.encode()).hexdigest()
            word_hash = hashlib.sha512((passenc + salt).encode()).hexdigest()
            if word_hash == wow:
                return word
    return hash

for db in dbs:
    if db.split(".")[-1] == "json":
        with open("dbs/"+db, encoding='latin-1') as f:
            loaded = json.loads(f.read())
            allData.append({
                "server": db.replace(".json", ""),
                "data": loaded
            })

words = []
wordlist = ""

if not os.path.isfile("DiavloWordlist.txt"):
    print("Si no sabes sobre wordlists. Simplemente dale a enter. Se te descargara una sola.")
    wordlist = input("Inserta el nombre de la wordlist » ")
    if wordlist == "":
        wordlist = "DiavloWordlist.txt"
        open("DiavloWordlist.txt","wb").write(requests.get("https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt").content)
else:
    wordlist = "DiavloWordlist.txt"

with open(wordlist, "r", encoding='latin-1') as f:
    lines = f.read().split("\n")
    for line in lines:
        words.append(line)

def crack_password(nickname):  
    dataFound = []
    found = False
    for server in allData:
        for data in server["data"]:
            if data['name'] == nickname:
                found = True
                hash, salt = "", ""
                hash = data["password"]
                if "salt" in data:
                    if not data["password"] == "null":
                        salt = data["salt"]
                        update_status(f"[ENCONTRADO] => {server['server']} | {nickname} | {data['password']} | {data['salt']}")
                else:
                    update_status(f"[ENCONTRADO] => {server['server']} | {nickname} | {data['password']}")
                tryBrute = bruteforce(hash, salt)
                if tryBrute != hash:
                    update_status(f"[DESENCRIPTADO] => {hash} | {tryBrute}")
    if not found:  
        update_status('[ERROR] => Contraseña no encontrada')
    print(Fore.RESET, end='')

root = tk.Tk()
root.title("DiavloPrime")

status_var = tk.StringVar()
status_label = tk.Label(root, textvariable=status_var, wraplength=500)
username_entry = tk.Entry(root)
crack_button = tk.Button(root, text="Crack", command=lambda: crack_password(username_entry.get()))

db_count_var = tk.StringVar() 
db_count_var.set(f'Databases: {len(dbs)}')


db_count_label = tk.Label(root, textvariable=db_count_var)
db_count_label.pack(padx=10, pady=10)

def update_status(message):
    status_var.set(message)

username_entry.pack(fill='x', padx=100, pady=10)
crack_button.pack(padx=10, pady=10)
status_label.pack(fill='x', padx=100, pady=10)

root.mainloop()

