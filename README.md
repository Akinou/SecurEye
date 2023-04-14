# SecurEye
Ce script utilise la bibliothèque Python "nmap" pour effectuer des scans de port sur un réseau ou un serveur cible. Le script peut scanner un seul hôte ou une plage d'adresses IP.

Pour chaque port ouvert détecté, le script vérifie si le service de port est associé à une vulnérabilité connue. Si une vulnérabilité est détectée, le script affiche une alerte avec une description de la vulnérabilité.

Le dictionnaire "known_vulnerabilities" contient des informations sur les vulnérabilités connues associées aux services de port. Vous pouvez le mettre à jour avec des informations sur les vulnérabilités connues pour votre environnement spécifique.

Ce script peut être utile pour les administrateurs de système qui souhaitent effectuer une vérification rapide de la sécurité de leur réseau ou de leurs serveurs en détect
