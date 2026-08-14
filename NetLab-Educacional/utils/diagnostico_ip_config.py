"""
Módulo para coleta completa de configuração IP (Layer 3).
Extrai IPv4, IPv6, gateway, DNS, DHCP, lease, rotas, etc.
"""

import subprocess
import re
import json
import ipaddress
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any


@dataclass
class ConfiguracaoIP:
    """Configuração de IP de uma interface."""
    nome_interface: str
    ipv4: str = ""
    mascara_ipv4: str = ""
    cidr: str = ""
    gateway_padrao: str = ""
    gateways_adicionais: List[str] = field(default_factory=list)
    dns_primario: str = ""
    dns_secundario: str = ""
    outros_dns: List[str] = field(default_factory=list)
    dhcp_ativado: bool = False
    dhcp_servidor: str = ""
    ipv6: List[str] = field(default_factory=list)
    mac_address: str = ""
    mtu: int = 1500
    
    def para_dict(self) -> Dict[str, Any]:
        """Converte para dicionário."""
        return asdict(self)


class DiagnosticoIPConfig:
    """Coleta dados de configuração IP completa."""

    @staticmethod
    def obter_configuracao_ip_windows() -> List[ConfiguracaoIP]:
        """
        Coleta configuração IP de todas as interfaces usando PowerShell.
        """
        configs = []
        
        try:
            # Comando PowerShell para obter Get-NetIPConfiguration completo
            cmd = (
                "Get-NetIPConfiguration -All | ForEach-Object { "
                "$iface = $_; "
                "$adapter = Get-NetAdapter -InterfaceIndex $iface.InterfaceIndex -ErrorAction SilentlyContinue; "
                "$ipv4 = $iface.IPv4Address; "
                "$ipv6 = @($iface.IPv6Address | ForEach-Object { $_.IPAddress }); "
                "$routes = Get-NetRoute -InterfaceIndex $iface.InterfaceIndex -ErrorAction SilentlyContinue; "
                "$gateways = @($routes | Where-Object {$_.DestinationPrefix -eq '0.0.0.0/0'} | ForEach-Object { $_.NextHop }) | Select-Object -Unique; "
                "$dhcp = (Get-NetIPInterface -InterfaceIndex $iface.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp; "
                "$dhcp_server = (Get-DhcpClientServer -InterfaceAlias $adapter.Name -ErrorAction SilentlyContinue).DhcpServer[0]; "
                "[PSCustomObject]@{ "
                "InterfaceName=$iface.InterfaceAlias; "
                "IPv4=$ipv4.IPAddress[0]; "
                "IPv4Prefix=$ipv4.PrefixLength[0]; "
                "Gateway=$gateways[0]; "
                "OtherGateways=@($gateways | Select-Object -Skip 1); "
                "DNS=$iface.DnsServer.ServerAddresses; "
                "IPv6=$ipv6; "
                "MAC=$adapter.MacAddress; "
                "MTU=$adapter.NdisPhysicalMediumType; "
                "DhcpEnabled=($dhcp -eq 'Enabled'); "
                "DhcpServer=$dhcp_server; "
                "} "
                "} | ConvertTo-Json"
            )
            
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=15,
                creationflags=0x08000000
            )
            
            if proc.returncode == 0 and proc.stdout.strip():
                try:
                    dados = json.loads(proc.stdout)
                    if isinstance(dados, dict):
                        dados = [dados]
                    
                    for item in dados:
                        if item and item.get("InterfaceName"):
                            ipv4 = item.get("IPv4", "")
                            prefix = item.get("IPv4Prefix", 24)
                            cidr = ""
                            
                            if ipv4:
                                try:
                                    cidr = str(ipaddress.ip_network(f"{ipv4}/{prefix}", strict=False))
                                except:
                                    cidr = ""
                            
                            dns_list = item.get("DNS", [])
                            dns_primario = dns_list[0] if dns_list else ""
                            dns_secundario = dns_list[1] if len(dns_list) > 1 else ""
                            outros_dns = dns_list[2:] if len(dns_list) > 2 else []
                            
                            config = ConfiguracaoIP(
                                nome_interface=item.get("InterfaceName", ""),
                                ipv4=ipv4,
                                mascara_ipv4=DiagnosticoIPConfig._prefix_para_mascara(prefix),
                                cidr=cidr,
                                gateway_padrao=item.get("Gateway", ""),
                                gateways_adicionais=item.get("OtherGateways", []),
                                dns_primario=dns_primario,
                                dns_secundario=dns_secundario,
                                outros_dns=outros_dns,
                                dhcp_ativado=item.get("DhcpEnabled", False),
                                dhcp_servidor=item.get("DhcpServer", ""),
                                ipv6=item.get("IPv6", []),
                                mac_address=item.get("MAC", ""),
                                mtu=item.get("MTU", 1500),
                            )
                            configs.append(config)
                except json.JSONDecodeError:
                    pass
        
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            pass
        
        return configs

    @staticmethod
    def _prefix_para_mascara(prefix: int) -> str:
        """Converte notação CIDR prefix para máscara decimal."""
        try:
            prefix = int(prefix)
            mascara = (0xffffffff >> (32 - prefix)) << (32 - prefix)
            octetos = [
                (mascara >> 24) & 0xff,
                (mascara >> 16) & 0xff,
                (mascara >> 8) & 0xff,
                mascara & 0xff,
            ]
            return ".".join(str(o) for o in octetos)
        except:
            return "255.255.255.0"

    @staticmethod
    def validar_configuracao(config: ConfiguracaoIP) -> List[str]:
        """Valida a configuração IP e retorna lista de problemas."""
        problemas = []
        
        # Verificar IPv4
        if not config.ipv4:
            problemas.append(f"{config.nome_interface} não possui endereço IPv4 configurado")
        elif config.ipv4.startswith("169.254."):
            problemas.append(f"{config.nome_interface} com APIPA: {config.ipv4} (sem DHCP disponível)")
        
        # Verificar gateway
        if config.ipv4 and not config.gateway_padrao:
            problemas.append(f"{config.nome_interface} sem gateway padrão")
        
        # Verificar gateway válido (deve estar na mesma rede)
        if config.ipv4 and config.gateway_padrao and config.cidr:
            try:
                rede = ipaddress.ip_network(config.cidr, strict=False)
                gateway = ipaddress.ip_address(config.gateway_padrao)
                if gateway not in rede:
                    problemas.append(f"Gateway {config.gateway_padrao} não está na rede {config.cidr}")
            except:
                pass
        
        # Verificar DNS
        if not config.dns_primario:
            problemas.append(f"{config.nome_interface} sem DNS primário configurado")
        
        # Verificar DHCP
        if config.dhcp_ativado and not config.dhcp_servidor:
            problemas.append(f"DHCP ativado mas nenhum servidor DHCP encontrado em {config.nome_interface}")
        
        return problemas
