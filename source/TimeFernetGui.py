import time
import base64

from cryptography.fernet import Fernet, InvalidToken  # Import de InvalidToken

from FernetGui import FernetGUI  # Correction de l'import

# Durée de vie du message en secondes
TTL = 30  

class TimeFernetGUI(FernetGUI):
    """
    Interface graphique pour un client de chat chiffré avec Fernet et TTL.
    """
    def encrypt(self, message):
        """
        Chiffre le message avec Fernet en utilisant un timestamp.
        """
        fernet = Fernet(self._key)  # Créer un objet Fernet
        current_time = int(time.time())  # Obtenir le timestamp actuel
        encrypted_message = fernet.encrypt_at_time(message.encode('utf-8'), current_time)  # Chiffrer avec timestamp
        return encrypted_message

    def decrypt(self, message) -> str:
        """
        Déchiffre le message avec Fernet et vérifie le TTL.
        """
        try:
            message = base64.b64decode(message['data'])  # Décoder le message chiffré
            decrypted = Fernet(self._key)  # Créer un objet Fernet
            current_time = int(time.time())  # Obtenir le timestamp actuel
            decrypted_message = decrypted.decrypt_at_time(message, TTL, current_time).decode('utf8')  # Déchiffrer avec TTL
            return decrypted_message
        except InvalidToken:
            self._log.info("Le message a expiré")
            return "Le message a expiré"  # Retourner un message d'erreur