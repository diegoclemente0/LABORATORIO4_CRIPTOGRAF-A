# LABORATORIO4_CRIPTOGRAF-A

# Laboratorio 4 - Cifrado Simétrico (DES, 3DES y AES-256)
 
El objetivo del laboratorio es implementar un programa en **Python**, utilizando la librería **PyCryptodome**, que permita **cifrar y descifrar texto** mediante los algoritmos **DES**, **3DES** y **AES-256** en modo **CBC (Cipher Block Chaining)**.

---

## 🧩 Descripción general

El programa solicita desde la terminal los siguientes datos:
- **Texto a cifrar**
- **Clave (key)** para cada algoritmo
- **Vector de inicialización (IV)** correspondiente

Luego ajusta las claves al tamaño requerido, realiza el cifrado y muestra:
- Clave final en hexadecimal  
- IV en hexadecimal  
- Texto cifrado (en formato hexadecimal)  
- Texto descifrado (que debe coincidir con el original)

---

## ⚙️ Requisitos

- Python 3.8 o superior  
- Librería **PyCryptodome**

Instalación:

```bash
pip install pycryptodome
