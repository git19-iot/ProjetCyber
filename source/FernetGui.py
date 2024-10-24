import logging
import base64
import dearpygui.dearpygui as dpg

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes

from chat_client import ChatClient
from generic_callback import GenericCallback
from CipheredGui import CipheredGUI, DEFAULT_VALUES  # Import corrigé


class FernetGUI(CipheredGUI):
    """
    Interface graphique pour un client de chat chiffré avec Fernet.
    """
    def __init__(self) -> None:
        super().__init__()
        self._key = None  # Clé de chiffrement Fernet

    def run_chat(self, sender, app_data) -> None:
        """
        Gère la connexion au serveur et génère la clé de chiffrement Fernet.
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

        # Génération de la clé Fernet à partir du mot de passe (SHA256 + base64)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode('utf-8'))
        self._key = base64.b64encode(digest.finalize())
        self._log.debug(f"Fernet key: {self._key.decode('utf-8')}")

        dpg.hide_item("connection_windows")
        dpg.show_item("chat_windows")
        dpg.set_value("screen", "Connecting")

    def encrypt(self, message):
        """
        Chiffre le message avec Fernet.
        """
        cipher = Fernet(self._key)  # Créer un objet Fernet
        message_bytes = message.encode('utf-8')  # Encoder le message en UTF-8
        return cipher.encrypt(message_bytes)  # Chiffrer le message

    def decrypt(self, message) -> str:
        """
        Déchiffre le message avec Fernet.
        """
        message = base64.b64decode(message['data'])  # Décoder le message chiffré
        decrypted = Fernet(self._key)  # Créer un objet Fernet
        decrypted_message = decrypted.decrypt(message).decode('utf8')  # Déchiffrer le message
        self._log.info(f"Message déchiffré : {decrypted_message}")
        return decrypted_message