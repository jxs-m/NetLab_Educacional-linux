"""
Módulo para análise de sub-redes e validação de configuração.
Detecta problemas como gateways inválidos, IPs duplicados, etc.
"""

import ipaddress
import subprocess
import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional


@dataclass
class AnalisSubrede:
    """Análise de uma sub-rede."""
    cidr: str
    endereco_rede: str
    endereco_broadcast: str
    mascara: str
    total_hosts: int
    gateway_dentro_rede: bool = False
    gateway_ip: str = ""
    primeiro_host: str = ""
    ultimo_host: str = ""
    classe: str = ""  # A, B, C, APIPA, Loopback, etc
    problemas: List[str] = field(default_factory=list)
    
    def para_dict(self) -> Dict[str, Any]:
        """Converte para dicionário."""
        return asdict(self)


class DiagnosticoSubrede:
    """Análise de sub-redes e validações."""

    @staticmethod
    def analisar_cidr(cidr: str, gateway: str = "") -> Optional[AnalisSubrede]:
        """
        Analisa um bloco CIDR e retorna informações detalhadas.
        """
        try:
            rede = ipaddress.ip_network(cidr, strict=False)
            
            # Determinar classe
            primeiro_octeto = int(str(rede.network_address).split(".")[0])
            if str(rede.network_address).startswith("127."):
                classe = "Loopback"
            elif str(rede.network_address).startswith("169.254."):
                classe = "APIPA (Link-Local)"
            elif 224 <= primeiro_octeto <= 239:
                classe = "Multicast (D)"
            elif 240 <= primeiro_octeto <= 255:
                classe = "Reservado (E)"
            elif primeiro_octeto < 128:
                classe = "A"
            elif primeiro_octeto < 192:
                classe = "B"
            else:
                classe = "C"
            
            # Verificar gateway
            gateway_ok = False
            if gateway:
                try:
                    gw_ip = ipaddress.ip_address(gateway)
                    gateway_ok = gw_ip in rede and gw_ip != rede.network_address and gw_ip != rede.broadcast_address
                except:
                    pass
            
            # Calcular hosts
            total_hosts = rede.num_addresses - 2 if rede.num_addresses > 2 else 0
            primeiro = str(list(rede.hosts())[0]) if rede.num_addresses > 2 else ""
            ultimo = str(list(rede.hosts())[-1]) if rede.num_addresses > 2 else ""
            
            problemas = []
            if gateway and not gateway_ok:
                problemas.append(f"Gateway {gateway} não está na rede {cidr}")
            
            return AnalisSubrede(
                cidr=cidr,
                endereco_rede=str(rede.network_address),
                endereco_broadcast=str(rede.broadcast_address),
                mascara=str(rede.netmask),
                total_hosts=total_hosts,
                gateway_dentro_rede=gateway_ok,
                gateway_ip=gateway,
                primeiro_host=primeiro,
                ultimo_host=ultimo,
                classe=classe,
                problemas=problemas,
            )
        except Exception as e:
            return None

    @staticmethod
    def detectar_ips_duplicados() -> Dict[str, List[str]]:
        """
        Detecta endereços IP duplicados na rede usando ARP.
        Retorna dict com IP como chave e lista de MACs como valor.
        """
        duplicados = {}
        
        try:
            # Usar PowerShell para obter ARP table completa
            cmd = (
                "Get-NetNeighbor -AddressFamily IPv4 | "
                "Select-Object IPAddress, LinkLayerAddress | "
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
                    
                    ip_mac_map = {}
                    for item in dados:
                        if item:
                            ip = item.get("IPAddress", "")
                            mac = item.get("LinkLayerAddress", "")
                            if ip and mac:
                                if ip not in ip_mac_map:
                                    ip_mac_map[ip] = []
                                ip_mac_map[ip].append(mac)
                    
                    # Encontrar IPs com múltiplos MACs
                    for ip, macs in ip_mac_map.items():
                        if len(set(macs)) > 1:  # MACs diferentes
                            duplicados[ip] = list(set(macs))
                
                except json.JSONDecodeError:
                    pass
        
        except Exception:
            pass
        
        return duplicados

    @staticmethod
    def validar_all_subnets(configs: List) -> List[str]:
        """
        Valida todas as sub-redes configuradas.
        """
        problemas = []
        
        for config in configs:
            if hasattr(config, 'cidr') and config.cidr:
                analise = DiagnosticoSubrede.analisar_cidr(config.cidr, config.gateway_padrao if hasattr(config, 'gateway_padrao') else "")
                if analise:
                    problemas.extend(analise.problemas)
        
        # Verificar IPs duplicados
        duplicados = DiagnosticoSubrede.detectar_ips_duplicados()
        for ip, macs in duplicados.items():
            problemas.append(f"IP duplicado detectado: {ip} ({len(macs)} MACs diferentes)")
        
        return problemas
