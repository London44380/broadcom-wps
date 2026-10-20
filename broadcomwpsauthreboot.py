#!/usr/bin/env python3
"""
WiFi Scanner et Détecteur de vulnérabilité Broadcom WPS
Basé sur : https://github.com/qkaiser/broadcom-wps
Article : https://www.01net.com/actualites/box-orange-sfr-peuvent-piratees-distance-faille-wi-fi.html

Ce script permet de :
1. Scanner les réseaux WiFi disponibles
2. Sélectionner un réseau spécifique
3. Vérifier s'il est vulnérable à la faille Broadcom WPS
4. (Labo) Redémarrer VOTRE propre routeur via son interface d'administration

Appareils vulnérables en France :
- Livebox 5 d'Orange (Sagemcom Fast5656)
- Box SFR "Box Plus" (NB6VAC)
- ZTE F680 v4

Utilisation :
    python wifi_scanner.py --interface wlan0 --ssid "NOM_DU_RESEAU"
    python wifi_scanner.py --interface wlan0 --scan-all
    python wifi_scanner.py --interface wlan0 --interactive

    # Labo : redémarrer votre propre routeur entre deux tests
    # (identifiants admin passés par variables d'environnement, jamais en CLI)
    LAB_ROUTER_USER=admin LAB_ROUTER_PASS=secret python wifi_scanner.py \
        --interface wlan0 --reboot aa:bb:cc:dd:ee:ff \
        --reboot-url http://192.168.1.1/reboot.cgi

ATTENTION : la détection ici est passive (analyse des beacons).
La présence d'un IE Broadcom seul n'est PAS une preuve (voir README du
dépôt qkaiser/broadcom-wps) : la confirmation définitive nécessite le test
actif du fingerprinter officiel. La fonction --reboot est réservée à vos
propres équipements de laboratoire : elle cible un routeur que vous
désignez explicitement, via son interface d'administration authentifiée.
N'utilisez cet outil que sur vos propres équipements ou avec autorisation.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterator, List, Optional, Tuple

try:
    from scapy.layers.dot11 import Dot11, Dot11Elt, RadioTap
    from scapy.packet import Packet
    from scapy.sendrecv import sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    Dot11 = Dot11Elt = RadioTap = Packet = sniff = None


@dataclass
class WiFiNetwork:
    ssid: str
    bssid: str
    channel: int
    rssi: int
    wps_advertised: bool = False
    broadcom_detected: bool = False
    security: List[str] = field(default_factory=list)
    vendor: str = "Unknown"
    model: str = "Unknown"


@dataclass
class VulnerabilityCheck:
    network: WiFiNetwork
    is_vulnerable: bool = False
    assessment: str = "UNKNOWN"
    broadcom_evidence: List[str] = field(default_factory=list)
    wps_detected: bool = False
    details: str = ""


class WiFiScanner:
    BROADCOM_IE_PREFIX = bytes.fromhex("00101802")  # OUI Broadcom 00:10:18, type 02
    WPS_IE_PREFIX = b"\x00\x50\xf2\x04"              # WFA : WPS
    WPA_IE_PREFIX = b"\x00\x50\xf2\x01"              # WFA : WPA

    WPS_TLV_MANUFACTURER = 0x1021
    WPS_TLV_MODEL_NAME = 0x1023

    VULNERABLE_DEVICES = {
        "Orange": ["Livebox 5", "Sagemcom Fast5656", "FAST5656"],
        "SFR": ["Box Plus", "NB6VAC", "NB6"],
        "ZTE": ["F680"],
        "Sagemcom": ["F@ST 3864", "F@ST 4353", "F@st 5336", "SagemcomFast"],
        "Netgear": ["CG3100", "CG3700B"],
        "Arcadyan": ["VRV9517"],
        "Askey": ["TCG3000", "RTF3505VW"],
        "Cisco": ["RV110W", "RV130W", "RV215W", "RV340W", "WAP121", "WAP150"],
    }

    def __init__(self, interface: str):
        self.interface = interface
        self.networks: List[WiFiNetwork] = []

    # ---------- interface / canal ----------

    def check_interface(self) -> bool:
        """True si l'interface existe ET est en mode monitor."""
        try:
            result = subprocess.run(
                ["iw", "dev", self.interface, "info"],
                capture_output=True, text=True, timeout=5
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0 and "type monitor" in result.stdout

    def _set_channel(self, channel: int) -> None:
        try:
            subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(channel)],
                timeout=2
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # ---------- parsing des trames ----------

    @staticmethod
    def _iter_information_elements(packet: "Packet") -> Iterator[Tuple[int, bytes]]:
        """Itère sur TOUS les Dot11Elt, y compris les IE 221 répétés/fragmentés."""
        if not SCAPY_AVAILABLE:
            return
        layer = packet.getlayer(Dot11Elt)
        for _ in range(512):
            if layer is None:
                return
            try:
                yield int(layer.ID), bytes(layer.info)
            except Exception:
                return
            layer = layer.payload.getlayer(Dot11Elt)

    @classmethod
    def _parse_wps_tlvs(cls, payload: bytes) -> Tuple[str, str]:
        """Extrait Manufacturer (0x1021) et Model Name (0x1023) des TLV WPS."""
        vendor, model = "Unknown", "Unknown"
        offset = 0
        while offset + 4 <= len(payload):
            kind = int.from_bytes(payload[offset:offset + 2], "big")
            length = int.from_bytes(payload[offset + 2:offset + 4], "big")
            offset += 4
            end = offset + length
            if end > len(payload):
                break
            value = payload[offset:end]
            offset = end
            if kind == cls.WPS_TLV_MANUFACTURER:
                vendor = value.rstrip(b"\x00").decode("utf-8", errors="replace").strip() or "Unknown"
            elif kind == cls.WPS_TLV_MODEL_NAME:
                model = value.rstrip(b"\x00").decode("utf-8", errors="replace").strip() or "Unknown"
        return vendor, model

    def _parse_beacon(self, packet: "Packet") -> Optional[WiFiNetwork]:
        if not SCAPY_AVAILABLE:
            return None
        try:
            dot11 = packet[Dot11]
            if int(dot11.type) != 0 or int(dot11.subtype) not in {5, 8}:
                return None
            bssid = str(dot11.addr2 or "").lower()
            if len(bssid.split(":")) != 6:
                return None

            # Tous les IE, en conservant les doublons (IE 221 fragmentés)
            ies: Dict[int, List[bytes]] = {}
            for eid, data in self._iter_information_elements(packet):
                ies.setdefault(eid, []).append(data)

            ssid_data = ies.get(0)
            if not ssid_data or not ssid_data[0]:
                return None  # SSID masqué ou trame incomplète
            ssid = ssid_data[0].decode("utf-8", errors="replace")

            channel = 0
            for eid in (3, 61):
                for data in ies.get(eid, []):
                    if data:
                        channel = data[0]
                        break
                if channel:
                    break

            security: List[str] = []
            wps_payload = b""
            broadcom_detected = False
            for data in ies.get(221, []):
                if data.startswith(self.BROADCOM_IE_PREFIX):
                    broadcom_detected = True
                elif data.startswith(self.WPS_IE_PREFIX):
                    # WPS souvent fragmenté sur plusieurs IE 221 : on concatène
                    wps_payload += data[len(self.WPS_IE_PREFIX):]
                elif data.startswith(self.WPA_IE_PREFIX):
                    security.append("WPA")
            if 48 in ies:
                security.append("WPA2/RSN")

            vendor, model = "Unknown", "Unknown"
            if wps_payload:
                vendor, model = self._parse_wps_tlvs(wps_payload)

            try:
                rssi = int(packet[RadioTap].dBm_AntSignal) if RadioTap in packet else -127
            except Exception:
                rssi = -127

            return WiFiNetwork(
                ssid=ssid, bssid=bssid, channel=channel, rssi=rssi,
                wps_advertised=bool(wps_payload),
                broadcom_detected=broadcom_detected,
                security=security, vendor=vendor, model=model,
            )
        except Exception:
            return None

    # ---------- accumulation des résultats ----------

    @staticmethod
    def _merge_network(existing: WiFiNetwork, new: WiFiNetwork) -> None:
        """Fusionne deux observations du même BSSID sans perdre d'information."""
        existing.rssi = max(existing.rssi, new.rssi)
        existing.channel = existing.channel or new.channel
        existing.wps_advertised = existing.wps_advertised or new.wps_advertised
        existing.broadcom_detected = existing.broadcom_detected or new.broadcom_detected
        if existing.vendor == "Unknown":
            existing.vendor = new.vendor
        if existing.model == "Unknown":
            existing.model = new.model
        for sec in new.security:
            if sec not in existing.security:
                existing.security.append(sec)

    def _packet_handler(self, packet: "Packet") -> None:
        network = self._parse_beacon(packet)
        if network is None:
            return
        existing = next((n for n in self.networks if n.bssid == network.bssid), None)
        if existing:
            self._merge_network(existing, network)
        else:
            self.networks.append(network)

    # ---------- scans ----------

    def scan_networks(self, timeout: float = 10.0, channel: Optional[int] = None,
                      quiet: bool = False) -> List[WiFiNetwork]:
        if not SCAPY_AVAILABLE:
            print("[-] scapy non disponible. Installez-le avec : pip install scapy")
            return []
        self.networks = []
        if channel:
            self._set_channel(channel)
        if not quiet:
            print(f"[*] Scan sur {self.interface} (timeout : {timeout}s)...")
        try:
            sniff(iface=self.interface, prn=self._packet_handler, timeout=timeout, store=0)
        except Exception as e:
            print(f"[!] Erreur de capture : {e}")
        self.networks.sort(key=lambda n: (-n.rssi, n.ssid))
        if not quiet:
            print(f"[+] Trouvé {len(self.networks)} réseaux")
        return self.networks

    def scan_all_channels(self, channels: Optional[List[int]] = None,
                          dwell_time: float = 0.5) -> List[WiFiNetwork]:
        if channels is None:
            channels = list(range(1, 14))
        all_networks: List[WiFiNetwork] = []
        for i, ch in enumerate(channels, 1):
            print(f"[*] Canal {ch} ({i}/{len(channels)})...", end="\r", flush=True)
            self._set_channel(ch)
            time.sleep(0.1)
            self.scan_networks(timeout=dwell_time, quiet=True)
            for net in self.networks:
                existing = next((n for n in all_networks if n.bssid == net.bssid), None)
                if existing:
                    self._merge_network(existing, net)
                else:
                    all_networks.append(net)
        all_networks.sort(key=lambda n: (-n.rssi, n.ssid))
        self.networks = all_networks
        print(f"\n[+] Trouvé {len(all_networks)} réseaux sur {len(channels)} canaux")
        return all_networks

    # ---------- évaluation ----------

    def check_vulnerability(self, network: WiFiNetwork) -> VulnerabilityCheck:
        result = VulnerabilityCheck(network=network)
        result.wps_detected = network.wps_advertised
        if network.broadcom_detected:
            result.broadcom_evidence.append("IE vendor-specific Broadcom (OUI 00:10:18) détecté")

        haystack = f"{network.vendor} {network.model}".lower()
        for vendor, models in self.VULNERABLE_DEVICES.items():
            if vendor.lower() in network.vendor.lower() or any(m.lower() in haystack for m in models):
                result.is_vulnerable = True
                result.assessment = "LIKELY_VULNERABLE"
                result.broadcom_evidence.append(
                    f"Appareil connu vulnérable : {vendor} ({network.vendor} {network.model})"
                )
                result.details = f"Correspond à la liste {vendor}"
                return result

        if network.wps_advertised and network.broadcom_detected:
            result.is_vulnerable = True
            result.assessment = "LIKELY_VULNERABLE"
            result.details = "WPS activé + IE Broadcom détecté (présomption, pas une preuve)"
        elif network.wps_advertised:
            result.assessment = "WPS_ENABLED"
        elif network.broadcom_detected:
            result.assessment = "BROADCOM_DETECTED"
        else:
            result.assessment = "NOT_VULNERABLE"
        return result

    # ---------- affichage ----------

    def print_networks(self, networks: Optional[List[WiFiNetwork]] = None) -> None:
        if networks is None:
            networks = self.networks
        if not networks:
            print("[-] Aucun réseau trouvé")
            return
        print("\n" + "=" * 105)
        print(f"{'#':<4}{'SSID':<26}{'BSSID':<18}{'Ch':>3}{'RSSI':>6}  {'Sécurité':<11}{'Appareil':<24}Statut")
        print("-" * 105)
        for i, net in enumerate(networks, 1):
            status_parts = []
            if net.wps_advertised:
                status_parts.append("WPS")
            if net.broadcom_detected:
                status_parts.append("BRCM")
            status = ",".join(status_parts) if status_parts else "-"
            security = "/".join(net.security) if net.security else "Open"
            device = f"{net.vendor} {net.model}".strip()
            if device in ("", "Unknown Unknown"):
                device = "?"
            print(f"{i:<4}{net.ssid[:26]:<26}{net.bssid:<18}{net.channel:>3}{net.rssi:>6}  "
                  f"{security[:11]:<11}{device[:24]:<24}{status}")
        print("-" * 105)
        print(f"Total : {len(networks)} réseaux")


def build_report(result: VulnerabilityCheck, extra: Optional[dict] = None) -> dict:
    net = result.network
    report = {
        "timestamp": datetime.now().isoformat(),
        "network": {
            "ssid": net.ssid,
            "bssid": net.bssid,
            "channel": net.channel,
            "rssi": net.rssi,
            "vendor": net.vendor,
            "model": net.model,
            "wps_advertised": net.wps_advertised,
            "broadcom_detected": net.broadcom_detected,
        },
        "vulnerability": {
            "assessment": result.assessment,
            "is_vulnerable": result.is_vulnerable,
            "wps_detected": result.wps_detected,
            "evidence": result.broadcom_evidence,
            "details": result.details,
        },
    }
    if extra:
        report.update(extra)
    return report


def _write_report(path: str, report: dict) -> None:
    try:
        with open(path, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"[+] Rapport sauvegardé : {path}")
    except OSError as e:
        print(f"[-] Impossible d'écrire {path} : {e}")


def print_result(result: VulnerabilityCheck) -> None:
    net = result.network
    print(f"\n{'=' * 60}\nRÉSULTAT : {result.assessment}\n{'=' * 60}")
    print(f"SSID:       {net.ssid}")
    print(f"BSSID:      {net.bssid}")
    print(f"Canal:      {net.channel}   RSSI: {net.rssi} dBm")
    print(f"Appareil:   {net.vendor} {net.model}")
    print(f"Sécurité:   {'/'.join(net.security) if net.security else 'Open'}")
    print(f"WPS:        {'oui' if net.wps_advertised else 'non'}")
    print(f"Broadcom:   {'oui' if net.broadcom_detected else 'non'}")
    print(f"Vulnérable: {'OUI' if result.is_vulnerable else 'NON'}")
    if result.details:
        print(f"Détails:    {result.details}")
    if result.broadcom_evidence:
        print("Preuves :")
        for e in result.broadcom_evidence:
            print(f"  - {e}")


def reboot_router(url: str, method: str = "POST", timeout: float = 10.0) -> bool:
    """Déclenche le redémarrage via l'endpoint d'administration d'un routeur
    qui vous appartient (usage labo). Les identifiants sont lus dans les
    variables d'environnement LAB_ROUTER_USER / LAB_ROUTER_PASS (auth Basic),
    jamais passés en argument de ligne de commande.
    """
    import base64
    import urllib.error
    import urllib.request
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        print("[-] URL invalide : schéma http/https attendu (ex : http://192.168.1.1/reboot.cgi)")
        return False

    req = urllib.request.Request(url, data=b"" if method == "POST" else None, method=method)
    user = os.environ.get("LAB_ROUTER_USER", "")
    password = os.environ.get("LAB_ROUTER_PASS", "")
    if user:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 400
    except urllib.error.HTTPError as e:
        print(f"[-] Le routeur a répondu HTTP {e.code} (endpoint ou identifiants à vérifier)")
        return False
    except Exception as e:
        print(f"[-] Échec du redémarrage : {e}")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="WiFi Scanner + Détection Broadcom WPS")
    parser.add_argument('--interface', type=str, required=True, help='Interface WiFi (ex : wlan0)')
    parser.add_argument('--ssid', type=str, default=None, help='SSID spécifique à vérifier')
    parser.add_argument('--list', action='store_true', help='Lister les réseaux (canal courant) et quitter')
    parser.add_argument('--scan-all', action='store_true', help='Scanner tous les canaux')
    parser.add_argument('--interactive', action='store_true', help='Mode interactif')
    parser.add_argument('--check-monitor', action='store_true', help='Vérifier le mode monitor')
    parser.add_argument('--enable-monitor', action='store_true', help='Activer le mode monitor (root requis)')
    parser.add_argument('--channels', type=str, default=None, help='Canaux à scanner (ex : "1,6,11")')
    parser.add_argument('--output', type=str, default=None, help='Fichier JSON de sortie')
    parser.add_argument('--reboot', type=str, default=None, metavar='BSSID',
                        help='LABO : redémarrer VOTRE routeur (BSSID) via son interface admin '
                             '(nécessite --reboot-url, confirmation obligatoire)')
    parser.add_argument('--reboot-url', type=str, default=None,
                        help='Endpoint admin de redémarrage (ex : http://192.168.1.1/reboot.cgi)')
    parser.add_argument('--reboot-method', choices=['GET', 'POST'], default='POST',
                        help='Méthode HTTP du redémarrage (défaut : POST)')
    args = parser.parse_args()

    scanner = WiFiScanner(args.interface)

    if args.check_monitor:
        ok = scanner.check_interface()
        print(f"[+] Mode monitor : {'ACTIF' if ok else 'INACTIF'}")
        return 0

    if args.enable_monitor:
        if os.name != "posix":
            print("[-] Uniquement disponible sous Linux")
            return 1
        if os.geteuid() != 0:
            print("[-] Root requis : relancez avec sudo")
            return 1
        commands = [
            ["ip", "link", "set", "dev", args.interface, "down"],
            ["iw", "dev", args.interface, "set", "type", "monitor"],
            ["ip", "link", "set", "dev", args.interface, "up"],
        ]
        try:
            for cmd in commands:
                subprocess.run(cmd, check=True, timeout=5)
            if scanner.check_interface():
                print(f"[+] Mode monitor activé sur {args.interface}")
            else:
                print("[-] Échec de l'activation du mode monitor")
        except FileNotFoundError as e:
            print(f"[-] Commande introuvable : {e.filename}")
        except subprocess.CalledProcessError as e:
            print(f"[-] Échec : {' '.join(e.cmd)}")
        except subprocess.TimeoutExpired:
            print("[-] Timeout pendant l'activation")
        return 0

    if args.reboot:
        bssid = args.reboot.strip().lower()
        if len(bssid.split(":")) != 6:
            print(f"[-] BSSID invalide : {args.reboot}")
            return 1
        if not args.reboot_url:
            print("[-] --reboot nécessite --reboot-url (endpoint admin de VOTRE routeur,")
            print("    ex : --reboot-url http://192.168.1.1/reboot.cgi)")
            return 1
        print("[!] LABO UNIQUEMENT : à n'utiliser que sur un routeur qui vous appartient.")
        print(f"    Routeur (BSSID) : {bssid}")
        print(f"    Endpoint admin   : {args.reboot_url}")
        print(f"    Méthode HTTP    : {args.reboot_method}")
        print("    Authentification : " +
              ("Basic (LAB_ROUTER_USER / LAB_ROUTER_PASS)" if os.environ.get("LAB_ROUTER_USER")
               else "aucune (définissez LAB_ROUTER_USER / LAB_ROUTER_PASS si nécessaire)"))
        try:
            answer = input("Tapez REBOOT pour confirmer : ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[-] Annulé")
            return 1
        if answer != "REBOOT":
            print("[-] Annulé")
            return 0
        if reboot_router(args.reboot_url, method=args.reboot_method):
            print(f"[+] Commande de redémarrage envoyée ({args.reboot_method} {args.reboot_url})")
            print("[*] Le routeur met généralement 1 à 2 minutes à revenir.")
            return 0
        return 1

    if not SCAPY_AVAILABLE:
        print("[!] scapy non disponible. Installez-le avec : pip install scapy")
        return 1

    if not scanner.check_interface():
        print(f"[!] {args.interface} n'est pas en mode monitor !")
        print(f"    Exécutez : sudo iw dev {args.interface} set type monitor")

    channels = None
    if args.channels:
        try:
            channels = [int(c.strip()) for c in args.channels.split(",") if c.strip()]
        except ValueError:
            print(f"[-] Canaux invalides : {args.channels}")
            return 1

    if args.list:
        networks = scanner.scan_networks(timeout=10)
        scanner.print_networks(networks)
        return 0

    if args.scan_all:
        networks = scanner.scan_all_channels(channels=channels)
        scanner.print_networks(networks)
        return 0

    if args.interactive:
        networks = scanner.scan_all_channels(channels=channels)
        scanner.print_networks(networks)
        if not networks:
            return 0
        print("\nSélectionnez un réseau (numéro) ou 'q' pour quitter :")
        try:
            choice = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            return 0
        if choice.lower() == "q":
            return 0
        try:
            idx = int(choice) - 1
        except ValueError:
            print("[-] Entrée invalide")
            return 1
        if not 0 <= idx < len(networks):
            print("[-] Sélection invalide")
            return 1
        selected = networks[idx]
        print(f"\n[*] Vérification de : {selected.ssid}")
        result = scanner.check_vulnerability(selected)
        print_result(result)
        if args.output:
            _write_report(args.output, build_report(result))
        return 0

    if args.ssid:
        networks = scanner.scan_all_channels(channels=channels)
        target = next((n for n in networks if n.ssid == args.ssid), None)
        if not target:
            print(f"[-] Réseau '{args.ssid}' non trouvé")
            return 1
        print(f"[+] Trouvé : {target.ssid} ({target.bssid})")
        result = scanner.check_vulnerability(target)
        print_result(result)
        if args.output:
            _write_report(args.output, build_report(result, extra={"target_ssid": args.ssid}))
        return 0

    parser.print_help()
    return 0


if __name__ == '__main__':
    sys.exit(main())
