"""
Módulo para verificações específicas do Windows.
Firewall, Defender, Drivers, Winsock, VPN, etc.
"""

import subprocess
import json
import re
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional


@dataclass
class VerificacaoWindows:
    """Resultado de verificações do Windows."""
    firewall_ativado: bool = False
    defender_ativado: bool = False
    winsock_ok: bool = True
    drivers_ndis_ok: bool = True
    vpn_detectada: bool = False
    adapters_virtuais: int = 0
    problemas: List[str] = field(default_factory=list)
    avisos: List[str] = field(default_factory=list)
    recomendacoes: List[str] = field(default_factory=list)
    
    def para_dict(self) -> Dict[str, Any]:
        """Converte para dicionário."""
        return asdict(self)


class DiagnosticoWindows:
    """Verificações específicas do Windows."""

    @staticmethod
    def verificar_firewall() -> bool:
        """
        Verifica se Windows Defender Firewall está ativado.
        """
        try:
            cmd = (
                "(Get-NetFirewallProfile -Profile Domain,Public,Private | "
                "Where-Object {$_.Enabled -eq $true} | "
                "Measure-Object).Count -gt 0"
            )
            
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=0x08000000
            )
            
            return "True" in proc.stdout
        except:
            return False

    @staticmethod
    def verificar_defender() -> bool:
        """
        Verifica se Windows Defender está ativado.
        """
        try:
            cmd = (
                "(Get-MpComputerStatus | "
                "Select-Object -ExpandProperty AntivirusEnabled)"
            )
            
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=0x08000000
            )
            
            return "True" in proc.stdout
        except:
            return False

    @staticmethod
    def verificar_winsock() -> bool:
        """
        Verifica integridade do Winsock.
        """
        try:
            # Executar netsh winsock show catalog
            proc = subprocess.run(
                ["netsh", "winsock", "show", "catalog"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=0x08000000
            )
            
            # Se não houver linhas de erro, Winsock está OK
            return "protocol" in proc.stdout.lower() and proc.returncode == 0
        except:
            return False

    @staticmethod
    def verificar_drivers_ndis() -> bool:
        """
        Verifica se drivers NDIS estão carregados.
        """
        try:
            cmd = (
                "Get-NetAdapter | "
                "Measure-Object | "
                "Select-Object -ExpandProperty Count"
            )
            
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=0x08000000
            )
            
            count = int(proc.stdout.strip())
            return count > 0
        except:
            return False

    @staticmethod
    def detectar_vpn() -> bool:
        """
        Detecta se VPN está ativa.
        """
        try:
            cmd = (
                "(Get-NetAdapter | "
                "Where-Object {$_.Name -like '*VPN*' -or $_.Name -like '*RAS*'} | "
                "Measure-Object).Count -gt 0"
            )
            
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=0x08000000
            )
            
            return "True" in proc.stdout
        except:
            return False

    @staticmethod
    def contar_adapters_virtuais() -> int:
        """
        Conta adapters virtuais/loopback.
        """
        try:
            cmd = (
                "Get-NetAdapter | "
                "Where-Object {$_.Name -like '*Virtual*' -or $_.Name -like '*Hyper*'} | "
                "Measure-Object | "
                "Select-Object -ExpandProperty Count"
            )
            
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=0x08000000
            )
            
            return int(proc.stdout.strip() or "0")
        except:
            return 0

    @staticmethod
    def diagnostico_windows_completo() -> VerificacaoWindows:
        """
        Executa diagnóstico completo do Windows.
        """
        verificacao = VerificacaoWindows()
        
        # Executar verificações
        verificacao.firewall_ativado = DiagnosticoWindows.verificar_firewall()
        verificacao.defender_ativado = DiagnosticoWindows.verificar_defender()
        verificacao.winsock_ok = DiagnosticoWindows.verificar_winsock()
        verificacao.drivers_ndis_ok = DiagnosticoWindows.verificar_drivers_ndis()
        verificacao.vpn_detectada = DiagnosticoWindows.detectar_vpn()
        verificacao.adapters_virtuais = DiagnosticoWindows.contar_adapters_virtuais()
        
        # Analisar e gerar recomendações
        if not verificacao.firewall_ativado:
            verificacao.avisos.append("Windows Firewall não está ativado")
            verificacao.recomendacoes.append("Ativar Windows Firewall para melhor segurança")
        else:
            verificacao.recomendacoes.append("Windows Firewall está ativado")
        
        if not verificacao.defender_ativado:
            verificacao.avisos.append("Windows Defender não está ativado")
            verificacao.recomendacoes.append("Ativar Windows Defender")
        else:
            verificacao.recomendacoes.append("Windows Defender está ativado")
        
        if not verificacao.winsock_ok:
            verificacao.problemas.append("Winsock pode estar corrompido")
            verificacao.recomendacoes.append("Execute 'netsh winsock reset catalog' como admin")
        
        if not verificacao.drivers_ndis_ok:
            verificacao.problemas.append("Drivers NDIS não carregados corretamente")
            verificacao.recomendacoes.append("Reinstale drivers de rede")
        
        if verificacao.vpn_detectada:
            verificacao.avisos.append("VPN ativa - dados passam pela VPN")
        
        return verificacao
