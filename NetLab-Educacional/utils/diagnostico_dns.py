"""
Módulo para diagnósticos DNS completos.
Resolução múltipla, tempos, fallback, verificação de poisoning, etc.
"""

import socket
import subprocess
import json
import re
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional


@dataclass
class ResultadoDNS:
    """Resultado de resolução DNS."""
    dominio: str
    sucesso: bool
    ipv4: List[str] = field(default_factory=list)
    ipv6: List[str] = field(default_factory=list)
    tempo_ms: float = 0.0
    servidor_dns: str = ""
    erro: str = ""
    
    def para_dict(self) -> Dict[str, Any]:
        """Converte para dicionário."""
        return asdict(self)


@dataclass
class DiagnosticoDNSCompleto:
    """Diagnóstico completo de DNS."""
    servidores_dns: List[str] = field(default_factory=list)
    dominios_testados: Dict[str, ResultadoDNS] = field(default_factory=dict)
    problemas: List[str] = field(default_factory=list)
    cache_dns_funcionando: bool = False
    dnssec_validacao: str = "Desconhecido"
    
    def para_dict(self) -> Dict[str, Any]:
        """Converte para dicionário."""
        data = asdict(self)
        data['dominios_testados'] = {k: v for k, v in self.dominios_testados.items()}
        return data


class DiagnosticoDNS:
    """Diagnósticos de DNS."""

    @staticmethod
    def obter_servidores_dns() -> List[str]:
        """
        Obtém lista de servidores DNS configurados.
        """
        servidores = []
        
        try:
            # Usar ipconfig /all para obter DNS
            proc = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=0x08000000
            )
            
            # Padrão: "   DNS Servers . . . . . . . . . . . : 8.8.8.8"
            matches = re.findall(r'DNS Servers\s*\.+\s*:\s*([\d\.]+)', proc.stdout)
            servidores.extend(matches)
            
            # Remove duplicatas
            servidores = list(set(servidores))
        
        except Exception:
            pass
        
        return servidores

    @staticmethod
    def resolver_dominio(dominio: str, usar_ipv6: bool = False) -> ResultadoDNS:
        """
        Resolve um domínio usando Python socket.
        """
        resultado = ResultadoDNS(dominio=dominio, sucesso=False)
        
        try:
            inicio = time.time()
            
            # Tentar resolver para IPv4
            if not usar_ipv6:
                try:
                    info = socket.getaddrinfo(dominio, None, socket.AF_INET)
                    for item in info:
                        ip = item[4][0]
                        if ip not in resultado.ipv4:
                            resultado.ipv4.append(ip)
                except:
                    pass
            
            # Tentar resolver para IPv6
            try:
                info = socket.getaddrinfo(dominio, None, socket.AF_INET6)
                for item in info:
                    ip = item[4][0]
                    if ip not in resultado.ipv6:
                        resultado.ipv6.append(ip)
            except:
                pass
            
            resultado.tempo_ms = (time.time() - inicio) * 1000
            resultado.sucesso = len(resultado.ipv4) > 0 or len(resultado.ipv6) > 0
        
        except Exception as e:
            resultado.erro = str(e)
        
        return resultado

    @staticmethod
    def resolver_com_nslookup(dominio: str, servidor_dns: str = "") -> ResultadoDNS:
        """
        Resolve um domínio usando nslookup (PowerShell/CMD).
        """
        resultado = ResultadoDNS(dominio=dominio, sucesso=False)
        
        try:
            inicio = time.time()
            
            if servidor_dns:
                cmd = f"nslookup {dominio} {servidor_dns}"
            else:
                cmd = f"nslookup {dominio}"
            
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=0x08000000,
                shell=True
            )
            
            # Parsear output
            # Padrão: "Address:  8.8.8.8"
            ipv4_matches = re.findall(r'Address:\s+([\d\.]+)', proc.stdout)
            for ip in ipv4_matches:
                if not ip.startswith("::") and ip not in resultado.ipv4:
                    resultado.ipv4.append(ip)
            
            ipv6_matches = re.findall(r'IPv6 Address:\s+([\da-f:]+)', proc.stdout)
            resultado.ipv6.extend(ipv6_matches)
            
            resultado.tempo_ms = (time.time() - inicio) * 1000
            resultado.sucesso = len(resultado.ipv4) > 0
            resultado.servidor_dns = servidor_dns
        
        except Exception as e:
            resultado.erro = str(e)
        
        return resultado

    @staticmethod
    def limpar_cache_dns() -> bool:
        """
        Limpa cache DNS do Windows.
        Requer privilégios de administrador.
        """
        try:
            proc = subprocess.run(
                ["ipconfig", "/flushdns"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=0x08000000
            )
            return proc.returncode == 0
        except:
            return False

    @staticmethod
    def diagnostico_dns_completo() -> DiagnosticoDNSCompleto:
        """
        Executa diagnóstico completo de DNS.
        """
        diagnostico = DiagnosticoDNSCompleto()
        
        # 1. Obter servidores DNS
        diagnostico.servidores_dns = DiagnosticoDNS.obter_servidores_dns()
        
        if not diagnostico.servidores_dns:
            diagnostico.problemas.append("Nenhum servidor DNS configurado!")
            return diagnostico
        
        # 2. Testar resoluções comuns
        dominios_teste = [
            "google.com",
            "github.com",
            "8.8.8.8.in-addr.arpa",  # Reverse DNS
        ]
        
        for dominio in dominios_teste:
            resultado = DiagnosticoDNS.resolver_dominio(dominio)
            diagnostico.dominios_testados[dominio] = resultado
            
            if not resultado.sucesso:
                diagnostico.problemas.append(f"Falha ao resolver {dominio}")
            elif resultado.tempo_ms > 1000:
                diagnostico.problemas.append(f"Resolução de {dominio} lenta: {resultado.tempo_ms:.0f}ms")
        
        # 3. Testar com cada servidor DNS
        for servidor in diagnostico.servidores_dns:
            resultado = DiagnosticoDNS.resolver_com_nslookup("google.com", servidor)
            if not resultado.sucesso:
                diagnostico.problemas.append(f"Servidor DNS {servidor} não respondendo")
        
        return diagnostico
