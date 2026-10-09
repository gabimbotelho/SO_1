from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import sys
import os
def cifrar_ficheiro(nome_ficheiro):
    """
    Cifra o ficheiro usando AES em modo ECB.
    O ficheiro cifrado é guardado em: <nome_ficheiro>.enc
    A chave é guardada em: <nome_ficheiro>.key

    É processado apenas um bloco AES de cada vez. Esta implementação é deliberadamente
    ineficiente, realizando operações de E/S muito pequenas e frequentes. Esta
    característica será utilizada nas fases seguintes para estudar e comparar diferentes
    formas de concorrência.
    """

    nome_cifrado = nome_ficheiro + ".enc"
    nome_chave = nome_ficheiro + ".key"

    # Gerar uma chave AES de 128 bits
    chave = get_random_bytes(16)

    # Guardar a chave
    with open(nome_chave, "wb") as f:
        f.write(chave)

    # Criar a cifra
    cipher = AES.new(chave, AES.MODE_ECB)

    with open(nome_ficheiro, "rb") as entrada, open(nome_cifrado, "wb") as saida:
        terminou = False

        while not terminou:
            # Ler apenas um bloco AES
            bloco = entrada.read(AES.block_size)

            # Se o bloco não estiver completo, chegámos ao fim do ficheiro
            if len(bloco) < AES.block_size:
                bloco = pad(bloco, AES.block_size)
                terminou = True

            # Cifrar exatamente um bloco
            bloco_cifrado = cipher.encrypt(bloco)

            # Escrever o bloco cifrado
            saida.write(bloco_cifrado)
def decifrar_ficheiro(nome_cifrado):
    """
    Decifra um ficheiro com extensão .enc.
    Por exemplo: dados.txt.enc
    A chave é obtida de: dados.txt.key
    O resultado é escrito em: dados.txt

    É processado apenas um bloco AES de cada vez. Ver observação no cifrar_ficheiro.
    """

    # Retirar a extensão .enc
    nome_original = nome_cifrado[:-4]

    # Nome do ficheiro que contém a chave
    nome_chave = nome_original + ".key"

    # Ler a chave
    with open(nome_chave, "rb") as f:
        chave = f.read()

    # Criar a cifra
    cipher = AES.new(chave, AES.MODE_ECB)

    with open(nome_cifrado, "rb") as entrada, open(nome_original, "wb") as saida:

        # Ler o primeiro bloco
        bloco = entrada.read(AES.block_size)

        while bloco:
            # Ler antecipadamente o próximo bloco
            proximo = entrada.read(AES.block_size)

            # Decifrar apenas o bloco atual
            bloco_decifrado = cipher.decrypt(bloco)

            # Se não existir próximo bloco, retirar o padding
            if not proximo:
                bloco_decifrado = unpad(bloco_decifrado, AES.block_size)

            saida.write(bloco_decifrado)
            bloco = proximo

def main():
    if len(sys.argv) < 3:
        print("Uso: pcrypt -c|-d {ficheiros}+ ")
        return

    modo = sys.argv[1]
    ficheiros = sys.argv[2:]

    if modo != '-c' and modo!= '-d':
        print(f"{modo}: modo não existe. Use -c ou -d")
        return

    for nome in ficheiros:

        if not os.path.exists(nome):
            print(f"{nome}: ficheiro nao existe")
            continue

        if modo == "-c":
            nome_enc = nome + ".enc"
            nome_key = nome + ".key"

            if os.path.exists(nome_enc):
                print(f"{nome_enc}: ficheiro já existe")
                continue

            if os.path.exists(nome_key):
                print(f"{nome_key}: ficheiro já existe")
                continue

            cifrar_ficheiro(nome)

        else: 
            if not nome.endswith(".enc"):
                print(f"{nome}: ficheiro não tem extensão .enc")
                continue

            nome_original = nome[:-4]
            nome_key = nome_original + ".key"

            if not os.path.exists(nome_key):
                print(f"{nome_key}: ficheiro nao existe")
                continue
            if os.path.exists(nome_original):
                print(f"{nome_original}: ficheiro já existe")
                continue

            decifrar_ficheiro(nome)


if __name__ == "__main__":
    main()
