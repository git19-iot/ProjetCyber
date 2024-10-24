import logging
import dearpygui.dearpygui as dpg

from chat_client import ChatClient
from generic_callback import GenericCallback
from basic_gui import BasicGUI, DEFAULT_VALUES

# Import des modules cryptographiques
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64

# Constantes pour la dérivation de clé
DM_SIZE = 16  # Taille de la clé dérivée
NB_ITERATIONS = 100000  # Nombre d'itérations PBKDF2HMAC
SALT = b"data"  # Sel pour PBKDF2HMAC

class CipheredGUI(BasicGUI):
    """
    Interface graphique pour un client de chat chiffré avec AES.
    """
    def __init__(self) -> None:
        super().__init__()
        self._key = None  # Clé de chiffrement AES

    def _create_connection_window(self) -> None:
        """
        Crée la fenêtre de connexion avec un champ pour le mot de passe.
        """
        with dpg.window(label="Connection", pos=(200, 150), width=400, height=300, show=False, tag="connection_windows"):
            for field in ["host", "port", "name"]:
                with dpg.group(horizontal=True):
                    dpg.add_text(field)
                    dpg.add_input_text(default_value=DEFAULT_VALUES[field], tag=f"connection_{field}")

            dpg.add_text("password")  # Ajout du champ mot de passe
            dpg.add_input_text(password=True, tag="connection_password")
            dpg.add_button(label="Connect", callback=self.run_chat)

    def run_chat(self, sender, app_data) -> None:
        """
        Gère la connexion au serveur et dérive la clé de chiffrement.
        """
        host = dpg.get_value("connection_host")
        port = int(dpg.get_value("connection_port"))
        name = dpg.get_value("connection_name")
        password = dpg.get_value("connection_password")
        self._log.info(f"Connecting {name}@{host}:{port}")

        self._callback = GenericCallback()
        self._client = ChatClient(host, port)
        self._client.start(self._callback)
        self._client.register(name)

        # Dérivation de la clé AES à partir du mot de passe
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), 
            length=DM_SIZE, 
            salt=SALT, 
            iterations=NB_ITERATIONS
        )
        self._key = kdf.derive(password.encode("utf8"))  # Dérivation de la clé
        self._log.info(f"self.key {self._key}")

        dpg.hide_item("connection_windows")
        dpg.show_item("chat_windows")
        dpg.set_value("screen", "Connecting")

    def encrypt(self, message):
        """
        Chiffre le message avec AES en mode CTR.
        """
        iv = os.urandom(16)  # Générer un IV aléatoire
        cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()  # Padding PKCS7
        padded_message = padder.update(message.encode()) + padder.finalize()  # Padder le message
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()  # Chiffrer le message
        return (iv, ciphertext)  # Retourner l'IV et le message chiffré

    def decrypt(self, message: bytes):
        """
        Déchiffre le message avec AES en mode CTR.
        """
        msg = base64.b64decode(message[1]['data'])  # Décoder le message chiffré
        iv = base64.b64decode(message[0]['data'])  # Décoder l'IV
        cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(msg) + decryptor.finalize()  # Déchiffrer le message
        unpadder = padding.PKCS7(128).unpadder()  # Dé-padding PKCS7
        unpadded = unpadder.update(decrypted) + unpadder.finalize()  # Dé-padder le message
        return unpadded.decode("utf-8")  # Retourner le message déchiffré

    def recv(self) -> None:
        """
        Réceptionne et déchiffre les messages.
        """
        if self._callback is not None:
            for msg in self._callback.get():
                user, msg = msg
                try:
                    # Essayer de déchiffrer avec la méthode standard (AES)
                    decrypted_msg = self.decrypt(msg)  
                except ValueError:
                    # Si le déchiffrement AES échoue, essayer Fernet
                    decrypted_msg = self.decrypt((b'', msg))  
                self.update_text_screen(f"{user} : {decrypted_msg}")
            self._callback.clear()

    def send(self, text):
        """
        Envoie le message chiffré.
        """
        encrypted_message = self.encrypt(text)  # Chiffrer le message
        self._client.send_message(encrypted_message)  # Envoyer le message

    def loop(self):
        """
        Boucle principale de l'interface graphique.
        """
        while dpg.is_dearpygui_running():
            self.recv()
            dpg.render_dearpygui_frame()
        dpg.destroy_context()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    client = CipheredGUI()
    client.create()
    client.loop()