"""
Módulo para diagnósticos da Camada Física (Layer 1).
Coleta informações sobre adapters de rede, velocidade, duplex, erros, etc.
"""

import subprocess
import re
import json
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any


@dataclass
class InfoCamadaFisica:
    """Informações de uma interface de rede (Camada Física)."""
    nome_interface: str
    descricao: str
    endereco_mac: str
    velocidade_mbps: int = 0
    modo_duplex: str = "Desconhecido"
    estado: str = "Desconhecido"  # Up, Down, Disabled
    mtu: int = 1500
    erros_crc: int = 0
    pacotes_descartados: int = 0
    erro_detectado: str = ""
    
    def para_dict(self) -> Dict[str, Any]:
        """Converte para dicionário."""
        return asdict(self)


class DiagnosticoCamadaFisica:
    """Coleta dados da camada física de interfaces de rede."""

    @staticmethod
    def obter_interfaces_windows() -> List[InfoCamadaFisica]:
        """
        Coleta informações de todas as interfaces de rede no Windows.
        Utiliza Get-NetAdapter para dados primários.
        """
        interfaces = []
        
        try:
            # Comando PowerShell para obter dados das interfaces
            cmd = (
                "Get-NetAdapter | ForEach-Object { "
                "$mac = $_.MacAddress; "
                "$int = $_; "
                "Get-NetAdapterStatistics -Name $_.Name -ErrorAction SilentlyContinue | ForEach-Object { "
                "$mtu = (Get-NetAdapterAdvancedProperty -Name $int.Name -RegistryKeyword 'MTU' -ErrorAction SilentlyContinue).DisplayValue; "
                "[PSCustomObject]@{ "
                "Name=$int.Name; "
                "Description=$int.InterfaceDescription; "
                "Mac=$mac; "
                "Speed=$int.LinkSpeed; "
                "Duplex=$int.FullDuplex; "
                "State=$int.Status; "
                "MTU=$mtu; "
                "ReceivedErrors=$_.ReceivedErrors; "
                "OutboundDiscardedPackets=$_.OutboundDiscardedPackets; "
                "} "
                "} "
                "} | ConvertTo-Json"
            )
            
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=0x08000000  # CREATE_NO_WINDOW
            )
            
            if proc.returncode == 0 and proc.stdout.strip():
                try:
                    dados = json.loads(proc.stdout)
                    # Se retornar um único objeto, converter para lista
                    if isinstance(dados, dict):
                        dados = [dados]
                    
                    for item in dados:
                        if item:
                            # Extrair velocidade (ex: "1 Gbps" -> 1000)
                            speed_str = str(item.get("Speed", "")).lower()
                            velocidade = DiagnosticoCamadaFisica._extrair_velocidade(speed_str)
                            
                            interface = InfoCamadaFisica(
                                nome_interface=item.get("Name", ""),
                                descricao=item.get("Description", ""),
                                endereco_mac=item.get("Mac", ""),
                                velocidade_mbps=velocidade,
                                modo_duplex="Full Duplex" if item.get("Duplex") else "Half Duplex",
                                estado=item.get("State", "Desconhecido"),
                                mtu=int(item.get("MTU", "1500") or "1500"),
                                erros_crc=int(item.get("ReceivedErrors", 0) or 0),
                                pacotes_descartados=int(item.get("OutboundDiscardedPackets", 0) or 0),
                            )
                            interfaces.append(interface)
                except json.JSONDecodeError:
                    pass
        
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            pass
        
        return interfaces

    @staticmethod
    def _extrair_velocidade(speed_str: str) -> int:
        """Extrai a velocidade em Mbps a partir de uma string."""
        if not speed_str:
            return 0
        
        # Padrões: "1 Gbps", "100 Mbps", etc.
        match = re.search(r'(\d+)\s*(gbps|mbps|kbps)?', speed_str, re.IGNORECASE)
        if match:
            valor = int(match.group(1))
            unidade = (match.group(2) or "mbps").lower()
            
            if "gbps" in unidade:
                return valor * 1000
            elif "kbps" in unidade:
                return valor // 1000
            else:
                return valor
        
        return 0

    @staticmethod
    def validar_configuracao_fisica(interface: InfoCamadaFisica) -> List[str]:
        """
        Analisa a interface e retorna lista de problemas encontrados.
        """
        problemas = []
        
        # Verificar estado
        if interface.estado.lower() != "up":
            problemas.append(f"Interface {interface.nome_interface} está {interface.estado.lower()}")
        
        # Verificar velocidade
        if interface.velocidade_mbps == 0:
            problemas.append(f"Velocidade de {interface.nome_interface} não detectada ou interface sem conexão")
        elif interface.velocidade_mbps < 10:
            problemas.append(f"Velocidade baixa em {interface.nome_interface}: {interface.velocidade_mbps} Mbps")
        
        # Verificar erros
        if interface.erros_crc > 0:
            problemas.append(f"{interface.erros_crc} erros CRC detectados em {interface.nome_interface}")
        
        # Verificar pacotes descartados
        if interface.pacotes_descartados > 0:
            problemas.append(f"{interface.pacotes_descartados} pacotes descartados em {interface.nome_interface}")
        
        # Verificar Half Duplex (problema potencial)
        if "half" in interface.modo_duplex.lower():
            problemas.append(f"Half Duplex detectado em {interface.nome_interface} - pode afetar performance")
        
        return problemas
