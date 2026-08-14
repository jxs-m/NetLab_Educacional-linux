"""
Módulo para análise de tráfego de rede.
Usa Scapy para capturar e analisar pacotes.
"""

import logging
import time
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

# Silenciar avisos do Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, conf
    conf.verb = 0
    SCAPY_DISPONIVEL = True
except ImportError:
    SCAPY_DISPONIVEL = False


@dataclass
class EstatisticaTrafego:
    """Estatísticas de tráfego capturado."""
    total_pacotes: int = 0
    pacotes_ipv4: int = 0
    pacotes_ipv6: int = 0
    pacotes_arp: int = 0
    pacotes_tcp: int = 0
    pacotes_udp: int = 0
    pacotes_icmp: int = 0
    pacotes_dns: int = 0
    bytes_totais: int = 0
    ips_origem: Dict[str, int] = field(default_factory=dict)
    ips_destino: Dict[str, int] = field(default_factory=dict)
    portas_destino: Dict[int, int] = field(default_factory=dict)
    protocolos: Dict[str, int] = field(default_factory=dict)
    broadcast_storms: List[str] = field(default_factory=list)
    flows_http: int = 0  # Conexões HTTP não-HTTPS
    anomalias: List[str] = field(default_factory=list)
    
    def para_dict(self) -> Dict[str, Any]:
        """Converte para dicionário."""
        return asdict(self)


class DiagnosticoTrafego:
    """Análise de tráfego de rede usando Scapy."""

    @staticmethod
    def capturar_trafego(
        interface: str,
        duracao_segundos: int = 10,
        filtro: str = ""
    ) -> EstatisticaTrafego:
        """
        Captura tráfego de uma interface por um período.
        """
        stats = EstatisticaTrafego()
        
        if not SCAPY_DISPONIVEL:
            stats.anomalias.append("Scapy não disponível para análise de tráfego")
            return stats
        
        try:
            pacotes_capturados = []
            
            # Função de callback para processar pacotes
            def processar_pacote(pkt):
                pacotes_capturados.append(pkt)
            
            # Executar sniffer
            print(f"Capturando tráfego em {interface} por {duracao_segundos}s...")
            sniffer = sniff(
                iface=interface,
                prn=processar_pacote,
                timeout=duracao_segundos,
                store=True,
                quiet=True
            )
            
            # Processar pacotes capturados
            for pkt in pacotes_capturados:
                stats.total_pacotes += 1
                stats.bytes_totais += len(pkt)
                
                # Classificar protocolos
                if pkt.haslayer(IP):
                    stats.pacotes_ipv4 += 1
                    ip_src = pkt[IP].src
                    ip_dst = pkt[IP].dst
                    stats.ips_origem[ip_src] = stats.ips_origem.get(ip_src, 0) + 1
                    stats.ips_destino[ip_dst] = stats.ips_destino.get(ip_dst, 0) + 1
                    
                    # Detectar broadcast storms
                    if ip_dst.endswith(".255") or ip_dst == "255.255.255.255":
                        broadcast_key = f"{ip_src} -> {ip_dst}"
                        if broadcast_key not in stats.broadcast_storms:
                            stats.broadcast_storms.append(broadcast_key)
                
                elif pkt.haslayer(IPv6):
                    stats.pacotes_ipv6 += 1
                
                if pkt.haslayer(ARP):
                    stats.pacotes_arp += 1
                
                if pkt.haslayer(TCP):
                    stats.pacotes_tcp += 1
                    porta_dst = pkt[TCP].dport
                    stats.portas_destino[porta_dst] = stats.portas_destino.get(porta_dst, 0) + 1
                    
                    # Detectar conexões HTTP (porta 80)
                    if porta_dst == 80:
                        stats.flows_http += 1
                        stats.anomalias.append("Tráfego HTTP não-criptografado detectado")
                
                elif pkt.haslayer(UDP):
                    stats.pacotes_udp += 1
                    if pkt.haslayer(DNS):
                        stats.pacotes_dns += 1
                
                if pkt.haslayer(ICMP):
                    stats.pacotes_icmp += 1
                
                # Contar protocolos
                for layer in pkt.layers():
                    proto_nome = layer.__name__
                    stats.protocolos[proto_nome] = stats.protocolos.get(proto_nome, 0) + 1
            
            # Detectar anomalias adicionais
            if stats.broadcast_storms:
                stats.anomalias.append(f"{len(stats.broadcast_storms)} broadcast storm(s) detectado(s)")
            
            # Portas suspeitas
            portas_suspeitas = {
                22: "SSH",
                3389: "RDP",
                21: "FTP",
                23: "Telnet",
            }
            
            for porta, nome in portas_suspeitas.items():
                if porta in stats.portas_destino and stats.portas_destino[porta] > 5:
                    stats.anomalias.append(f"Tráfego em {nome} (porta {porta}) detectado")
        
        except Exception as e:
            stats.anomalias.append(f"Erro ao capturar tráfego: {str(e)}")
        
        return stats
