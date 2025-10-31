
from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii

# Ajustar clave al tamaño requerido
def ajustar_clave(clave_ingresada, tamaño_requerido):
    clave_bytes = clave_ingresada.encode('utf-8')
    if len(clave_bytes) < tamaño_requerido:
        clave_bytes += get_random_bytes(tamaño_requerido - len(clave_bytes))
        print(f"  Clave completada hasta {tamaño_requerido} bytes")
    elif len(clave_bytes) > tamaño_requerido:
        clave_bytes = clave_bytes[:tamaño_requerido]
        print(f"  Clave truncada a {tamaño_requerido} bytes")
    return clave_bytes

# Cifrar con DES
def cifrar_des(texto, clave, iv):
    cifrador = DES.new(clave, DES.MODE_CBC, iv)
    return cifrador.encrypt(pad(texto.encode('utf-8'), DES.block_size))

# Descifrar con DES
def descifrar_des(texto_cifrado, clave, iv):
    cifrador = DES.new(clave, DES.MODE_CBC, iv)
    return unpad(cifrador.decrypt(texto_cifrado), DES.block_size).decode('utf-8')

# Cifrar con 3DES
def cifrar_3des(texto, clave, iv):
    cifrador = DES3.new(clave, DES3.MODE_CBC, iv)
    return cifrador.encrypt(pad(texto.encode('utf-8'), DES3.block_size))

# Descifrar con 3DES
def descifrar_3des(texto_cifrado, clave, iv):
    cifrador = DES3.new(clave, DES3.MODE_CBC, iv)
    return unpad(cifrador.decrypt(texto_cifrado), DES3.block_size).decode('utf-8')

# Cifrar con AES-256
def cifrar_aes(texto, clave, iv):
    cifrador = AES.new(clave, AES.MODE_CBC, iv)
    return cifrador.encrypt(pad(texto.encode('utf-8'), AES.block_size))

# Descifrar con AES-256
def descifrar_aes(texto_cifrado, clave, iv):
    cifrador = AES.new(clave, AES.MODE_CBC, iv)
    return unpad(cifrador.decrypt(texto_cifrado), AES.block_size).decode('utf-8')

# Mostrar bytes en hexadecimal
def mostrar_hex(datos, nombre):
    print(f"{nombre}: {' '.join([binascii.hexlify(datos)[i:i+2].decode() for i in range(0, len(datos)*2, 2)])}")

# Inputs
def main():
    texto = input("\nIngrese el texto a cifrar: ")

    clave_des = ajustar_clave(input("\nClave para DES: "), 8)
    iv_des = ajustar_clave(input("IV para DES (8 bytes): "), 8)

    clave_3des = ajustar_clave(input("\nClave para 3DES: "), 24)
    iv_3des = ajustar_clave(input("IV para 3DES (8 bytes): "), 8)

    clave_aes = ajustar_clave(input("\nClave para AES-256: "), 32)
    iv_aes = ajustar_clave(input("IV para AES-256 (16 bytes): "), 16)

    print("\n" + "=" * 60)
    print("RESULTADOS")

    print("\n--- DES ---")
    texto_cifrado = cifrar_des(texto, clave_des, iv_des)
    mostrar_hex(clave_des, "Clave DES")
    mostrar_hex(iv_des, "IV DES")
    mostrar_hex(texto_cifrado, "Texto cifrado DES")
    print("Texto descifrado:", descifrar_des(texto_cifrado, clave_des, iv_des))

    print("\n--- 3DES ---")
    texto_cifrado = cifrar_3des(texto, clave_3des, iv_3des)
    mostrar_hex(clave_3des, "Clave 3DES")
    mostrar_hex(iv_3des, "IV 3DES")
    mostrar_hex(texto_cifrado, "Texto cifrado 3DES")
    print("Texto descifrado:", descifrar_3des(texto_cifrado, clave_3des, iv_3des))

    print("\n--- AES-256 ---")
    texto_cifrado = cifrar_aes(texto, clave_aes, iv_aes)
    mostrar_hex(clave_aes, "Clave AES-256")
    mostrar_hex(iv_aes, "IV AES-256")
    mostrar_hex(texto_cifrado, "Texto cifrado AES-256")
    print("Texto descifrado:", descifrar_aes(texto_cifrado, clave_aes, iv_aes))

if __name__ == "__main__":
    main()
