import nmap

# Fonction pour scanner un hôte ou une plage d'adresses IP
def scan_host(target):
    # Création d'un objet de scan Nmap
    scanner = nmap.PortScanner()

    # Exécution du scan sur l'hôte ou la plage d'adresses IP cible
    scanner.scan(target)

    # Affichage des informations de scan pour chaque hôte
    for host in scanner.all_hosts():
        print("----------------------------------------------------")
        print("Host : %s (%s)" % (host, scanner[host].hostname()))
        print("State : %s" % scanner[host].state())
        
        # Affichage des ports ouverts et des services associés pour chaque hôte
        for proto in scanner[host].all_protocols():
            print("Protocol : %s" % proto)

            lport = scanner[host][proto].keys()
            lport = sorted(lport)
            for port in lport:
                print("Port : %s\tService : %s" % (port, scanner[host][proto][port]['name']))

                # Vérification si le port est associé à une vulnérabilité connue
                if scanner[host][proto][port]['name'] in known_vulnerabilities:
                    print("ALERT: Vulnerability detected for port %s - %s" % (port, scanner[host][proto][port]['name']))
                    print("\tDescription: %s" % known_vulnerabilities[scanner[host][proto][port]['name']])

# Dictionnaire des vulnérabilités connues associées aux services de port
known_vulnerabilities = {
    "http": "Vulnérabilité XSS possible",
    "ssh": "Failles de sécurité connues dans les anciennes versions de SSH",
    "ftp": "Attaques d'injection de commande possible",
    "telnet": "Données non cryptées pouvant être interceptées",
    "smtp": "Vulnérabilités connues dans les serveurs SMTP",
    "https": "Vulnérabilités SSL/TLS connues",
    "smb": "Failles de sécurité connues dans les anciennes versions de SMB",
    "snmp": "Mots de passe de communauté SNMP par défaut",
}

# Demande de l'adresse IP ou de la plage d'adresses IP à scanner
target = input("Enter IP address or range to scan: ")

# Lancement du scan sur l'hôte ou la plage d'adresses IP cible
scan_host(target)
