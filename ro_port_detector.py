"""
ro_port_detector.py
===================
Modulo compartido para auto-detectar el puerto del Map Server de RO.

Estrategia en dos capas:
  1. METODO RAPIDO: psutil -> busca el proceso ragexe.exe y lee sus
     conexiones TCP establecidas. Excluye puertos conocidos de Login (6900)
     y Char Server (6121) para quedarse con el Map Server.

  2. METODO FALLBACK (firma de paquetes): sniffea todo TCP y detecta el
     puerto mirando si los primeros 2 bytes del payload coinciden con algun
     Packet ID conocido de RO. Util si psutil no puede acceder al proceso.

Uso rapido:
    from ro_port_detector import RoPortDetector

    det = RoPortDetector()
    port, ip = det.detect()
    if port:
        print(f"Map Server: {ip}:{port}")
"""

import time
import threading
import psutil
from scapy.all import sniff, TCP, Raw, IP, conf

# --- Configuracion -------------------------------------------------------

# Nombres posibles del ejecutable del cliente RO
RO_PROCESS_NAMES = [
    'ragexe.exe',
    'ragnarok.exe',
    '2ragexe.exe',
    'Ragnarok.exe',
    'RagnarokOnline.exe',
    'client.exe',
    'ro.exe',
]

# Puertos que NO son el Map Server (login, char, web, etc.)
EXCLUDED_PORTS = {6900, 6121, 6123, 80, 443, 8080, 3306}

# Packet IDs comunes del Map Server (servidor -> cliente)
# Usados para deteccion por firma cuando psutil falla
RO_SERVER_PACKET_SIGNATURES = {
    b'\xc8\x08',  # ZC_NOTIFY_ACT3       (dano fisico)
    b'\xdf\x0a',  # ZC_NOTIFY_SKILL_DAMAGE
    b'\x9e\x00',  # ZC_ITEM_FALL_ENTRY   (item en suelo)
    b'\x4b\x08',  # ZC_ITEM_FALL_ENTRY3
    b'\xdd\x0a',  # ZC_ITEM_FALL_ENTRY5
    b'\x86\x00',  # ZC_NOTIFY_PLAYERMOVE (movimiento jugador)
    b'\x7b\x00',  # ZC_NOTIFY_MOVE
    b'\x2e\x01',  # ZC_NOTIFY_NEWENTRY   (jugador aparecio)
    b'\x29\x02',  # ZC_NOTIFY_HP_TO_GROUPM
    b'\xc3\x00',  # ZC_ACK_WHISPER
}

# --- Detector ---------------------------------------------------------------


class RoPortDetector:
    """
    Detecta automaticamente el puerto y la IP del Map Server de RO.

    Ejemplo:
        det = RoPortDetector(on_detected=lambda port, ip: print(port, ip))
        det.start_background_watch()   # vigila y re-detecta si cambia
    """

    def __init__(self, on_detected=None, poll_interval: float = 5.0):
        """
        Args:
            on_detected: callback(port: int, server_ip: str) cuando se detecta
                         o cambia el puerto del Map Server.
            poll_interval: segundos entre reintentos de psutil.
        """
        self.on_detected   = on_detected
        self.poll_interval = poll_interval

        self.port:      int | None = None
        self.server_ip: str | None = None
        self._lock     = threading.Lock()
        self._stop_evt = threading.Event()

    # -- Deteccion via psutil ------------------------------------------------

    def detect_via_psutil(self) -> tuple:
        """
        Busca el proceso del cliente RO e inspecciona sus conexiones TCP.
        Retorna (puerto, ip_servidor) del Map Server, o (None, None).
        """
        for proc in psutil.process_iter(['name', 'pid']):
            try:
                if proc.name().lower() not in [p.lower() for p in RO_PROCESS_NAMES]:
                    continue

                conns = proc.net_connections(kind='tcp')
                established = [
                    c for c in conns
                    if c.status == 'ESTABLISHED'
                    and c.raddr
                    and c.raddr.port not in EXCLUDED_PORTS
                ]

                if not established:
                    # Si todos los puertos estan en EXCLUDED_PORTS, igual retornar algo
                    all_conns = [c for c in conns if c.status == 'ESTABLISHED' and c.raddr]
                    if all_conns:
                        best = max(all_conns, key=lambda c: c.raddr.port)
                        return best.raddr.port, best.raddr.ip
                    continue

                # Si hay varias conexiones no excluidas, preferir la de mayor puerto
                best = max(established, key=lambda c: c.raddr.port)
                return best.raddr.port, best.raddr.ip

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return None, None

    # -- Deteccion via firma de paquetes -------------------------------------

    def detect_via_packets(self, timeout: float = 15.0) -> tuple:
        """
        Escucha todo el trafico TCP y detecta el Map Server cuando ve
        paquetes con firma RO conocida.
        Retorna (puerto, ip_servidor) o (None, None) si agota el timeout.
        """
        result = {'port': None, 'ip': None}

        def on_packet(pkt):
            if result['port']:
                return
            if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
                return

            payload = bytes(pkt[Raw].load)
            if len(payload) < 2:
                return

            pkt_id = payload[0:2]
            if pkt_id in RO_SERVER_PACKET_SIGNATURES:
                result['port'] = pkt[TCP].sport
                result['ip']   = pkt[IP].src

        print("[~] Escuchando paquetes RO para detectar Map Server (fallback)...")
        sniff(
            filter="tcp",
            prn=on_packet,
            store=False,
            timeout=timeout,
            stop_filter=lambda _: bool(result['port']),
        )

        return result['port'], result['ip']

    # -- API principal -------------------------------------------------------

    def detect(self, packet_fallback_timeout: float = 15.0) -> tuple:
        """
        Intenta detectar el puerto del Map Server.
        Primero psutil, luego fallback por paquetes.

        Returns:
            (port, server_ip) o (None, None) si no se detecta.
        """
        # Metodo 1: psutil (instantaneo)
        port, ip = self.detect_via_psutil()
        if port:
            self._update(port, ip, method="psutil")
            return port, ip

        print("[!] psutil no encontro el proceso RO. Intentando deteccion por paquetes...")

        # Metodo 2: firma de paquetes
        port, ip = self.detect_via_packets(timeout=packet_fallback_timeout)
        if port:
            self._update(port, ip, method="firma de paquetes")
            return port, ip

        return None, None

    def _update(self, port: int, ip: str, method: str = ""):
        """Actualiza el estado y dispara el callback si cambio."""
        with self._lock:
            changed = (port != self.port or ip != self.server_ip)
            self.port      = port
            self.server_ip = ip

        if changed:
            label = f"[+] Map Server detectado via {method}: {ip}:{port}" if method else \
                    f"[+] Map Server actualizado: {ip}:{port}"
            print(label)
            if self.on_detected:
                self.on_detected(port, ip)

    # -- Vigilancia continua en background ----------------------------------

    def start_background_watch(self):
        """
        Inicia un thread que re-detecta el puerto periodicamente.
        Util para cuando el jugador se mueve entre mapas/reloguea.
        """
        t = threading.Thread(target=self._watch_loop, daemon=True)
        t.start()
        return t

    def _watch_loop(self):
        while not self._stop_evt.is_set():
            port, ip = self.detect_via_psutil()
            if port:
                self._update(port, ip, method="psutil [recheck]")
            time.sleep(self.poll_interval)

    def stop(self):
        self._stop_evt.set()

    @property
    def ready(self) -> bool:
        return self.port is not None


# --- Utilidad rapida standalone -------------------------------------------

def quick_detect(verbose: bool = True) -> tuple:
    """
    Funcion de conveniencia para detectar el puerto Map Server rapidamente.

    Ejemplo:
        port, ip = quick_detect()
    """
    det = RoPortDetector()
    port, ip = det.detect()
    if not port and verbose:
        print("[!] No se pudo detectar el Map Server. Esta el juego abierto y conectado?")
    return port, ip


if __name__ == "__main__":
    print("=== RO Port Detector ===")
    port, ip = quick_detect()
    if port:
        print(f"[OK] Map Server: {ip}:{port}")
    else:
        print("[!!] No detectado.")
