"""
Módulo para descoberta de rede e identificação de dispositivos.
Varredura ARP, ICMP, NBNS, mDNS, SSDP.
"""

import subprocess
import re
import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

try:
    from scapy.all import Ether, ARP, conf, srp, IP, ICMP
    SCAPY_DISPONIVEL = True
except ImportError:
    SCAPY_DISPONIVEL = False


@dataclass
class DispositivoRede:
    """Informações de um dispositivo na rede."""
    ip: str
    mac: str
    hostname: str = ""
    fabricante: str = ""
    porta_aberta: bool = False
    portas_abertas: List[int] = field(default_factory=list)
    tempo_resposta_ms: float = 0.0
    tipo_dispositivo: str = ""  # PC, Impressora, Roteador, etc
    
    def para_dict(self) -> Dict[str, Any]:
        """Converte para dicionário."""
        return asdict(self)


class DiscoveriaRede:
    """Descoberta de dispositivos na rede."""

    @staticmethod
    def varrer_arp(interface: str, subnet: str = "192.168.1.0/24") -> List[DispositivoRede]:
        """
        Realiza varredura ARP na sub-rede especificada.
        """
        dispositivos = []
        
        if not SCAPY_DISPONIVEL:
            return dispositivos
        
        try:
            # Criar pacotes ARP
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
            
            # Enviar e receber respostas
            answered, unanswered = srp(arp_request, iface=interface, timeout=2, verbose=False)
            
            for sent, rcv in answered:
                dispositivo = DispositivoRede(
                    ip=rcv.psrc,
                    mac=rcv.hwsrc,
                )
                dispositivos.append(dispositivo)
        
        except Exception as e:
            pass
        
        return dispositivos

    @staticmethod
    def obter_dispositivos_conectados() -> List[DispositivoRede]:
        """
        Obtém lista de dispositivos conectados usando ARP table do Windows.
        """
        dispositivos = []
        
        try:
            # Usar PowerShell para obter ARP neighbors
            cmd = (
                "Get-NetNeighbor -AddressFamily IPv4 -State Reachable | "
                "Select-Object IPAddress, LinkLayerAddress, State | "
                "ConvertTo-Json"
            )
            
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=0x08000000
            )
            
            if proc.returncode == 0 and proc.stdout.strip():
                try:
                    dados = json.loads(proc.stdout)
                    if isinstance(dados, dict):
                        dados = [dados]
                    
                    for item in dados:
                        if item:
                            dispositivo = DispositivoRede(
                                ip=item.get("IPAddress", ""),
                                mac=item.get("LinkLayerAddress", ""),
                            )
                            dispositivos.append(dispositivo)
                except json.JSONDecodeError:
                    pass
        
        except Exception:
            pass
        
        return dispositivos

    @staticmethod
    def resolver_hostname(ip: str) -> str:
        """
        Tenta resolver hostname a partir de IP.
        """
        try:
            import socket
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return ""

    @staticmethod
    def detectar_tipo_dispositivo(ip: str, portas_abertas: List[int]) -> str:
        """
        Tenta detectar o tipo de dispositivo baseado em portas abertas.
        """
        # Portas comuns por tipo de dispositivo
        if 443 in portas_abertas or 80 in portas_abertas:
            if 9100 in portas_abertas:
                return "Impressora com web"
            return "Servidor Web / PC"
        
        if 3306 in portas_abertas or 5432 in portas_abertas:
            return "Servidor de Banco de Dados"
        
        if 3389 in portas_abertas:
            return "Windows RDP"
        
        if 22 in portas_abertas:
            return "Linux/Unix SSH"
        
        if 9100 in portas_abertas or 515 in portas_abertas:
            return "Impressora de Rede"
        
        if 5000 in portas_abertas or 8080 in portas_abertas:
            return "Serviço Custom"
        
        return "Dispositivo Genérico"

    @staticmethod
    def descoberta_completa() -> List[DispositivoRede]:
        """
        Executa descoberta completa de rede.
        """
        dispositivos = DiscoveriaRede.obter_dispositivos_conectados()
        
        # Enriquecer dados
        for dispositivo in dispositivos:
            dispositivo.hostname = DiscoveriaRede.resolver_hostname(dispositivo.ip)
        
        return dispositivos
