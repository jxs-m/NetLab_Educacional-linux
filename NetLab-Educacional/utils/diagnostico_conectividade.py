"""
Módulo para testes avançados de conectividade.
ICMP (ping), TCP, UDP, traceroute, latência, perda de pacotes.
"""

import subprocess
import re
import socket
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Tuple


@dataclass
class ResultadoPing:
    """Resultado de um ping."""
    alvo: str
    sucesso: bool
    tempo_ms: float = 0.0
    perda_percentual: float = 0.0
    tempo_minimo: float = 0.0
    tempo_maximo: float = 0.0
    tempo_medio: float = 0.0
    desvio_padrao: float = 0.0
    ttl_resposta: int = 0
    
    def para_dict(self) -> Dict[str, Any]:
        """Converte para dicionário."""
        return asdict(self)


@dataclass
class ResultadoTesteConexao:
    """Resultado de teste de conexão TCP/UDP."""
    alvo: str
    porta: int
    protocolo: str  # TCP ou UDP
    conectado: bool
    tempo_ms: float = 0.0
    erro: str = ""
    
    def para_dict(self) -> Dict[str, Any]:
        """Converte para dicionário."""
        return asdict(self)


@dataclass
class ResultadoTraceroute:
    """Resultado de traceroute."""
    alvo: str
    hops: List[Dict[str, Any]] = field(default_factory=list)
    tempo_total_ms: float = 0.0
    
    def para_dict(self) -> Dict[str, Any]:
        """Converte para dicionário."""
        return asdict(self)


class DiagnosticoConectividade:
    """Testes de conectividade em múltiplas camadas."""

    @staticmethod
    def ping(alvo: str, pacotes: int = 4, timeout: int = 5) -> ResultadoPing:
        """
        Executa ping ICMP para um alvo.
        """
        resultado = ResultadoPing(alvo=alvo, sucesso=False)
        
        try:
            # Windows: usar comando ping nativo
            cmd = ["ping", "-n", str(pacotes), "-w", str(timeout * 1000), alvo]
            
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 5,
                creationflags=0x08000000
            )
            
            if proc.returncode == 0:
                resultado.sucesso = True
                
                # Extrair estatísticas
                # Padrão: "time=45ms" ou "time<1ms"
                times = re.findall(r'time[<=](\d+)ms', proc.stdout)
                if times:
                    tempos = [float(t) for t in times]
                    resultado.tempo_ms = tempos[0]  # Primeiro pacote
                    resultado.tempo_minimo = min(tempos)
                    resultado.tempo_maximo = max(tempos)
                    resultado.tempo_medio = sum(tempos) / len(tempos)
                
                # Extrair TTL
                ttl_match = re.search(r'TTL=(\d+)', proc.stdout)
                if ttl_match:
                    resultado.ttl_resposta = int(ttl_match.group(1))
                
                # Extrair perda
                perda_match = re.search(r'(\d+)%\s+loss', proc.stdout)
                if perda_match:
                    resultado.perda_percentual = float(perda_match.group(1))
        
        except subprocess.TimeoutExpired:
            resultado.erro = "Timeout"
        except Exception as e:
            resultado.erro = str(e)
        
        return resultado

    @staticmethod
    def teste_tcp(alvo: str, porta: int, timeout: int = 3) -> ResultadoTesteConexao:
        """
        Testa conectividade TCP para um alvo:porta.
        """
        resultado = ResultadoTesteConexao(
            alvo=alvo,
            porta=porta,
            protocolo="TCP",
            conectado=False
        )
        
        try:
            inicio = time.time()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            try:
                sock.connect((alvo, porta))
                resultado.conectado = True
                resultado.tempo_ms = (time.time() - inicio) * 1000
            except socket.timeout:
                resultado.erro = "Timeout"
            except socket.refused:
                resultado.erro = "Conexão recusada"
            except Exception as e:
                resultado.erro = str(e)
            finally:
                sock.close()
        
        except Exception as e:
            resultado.erro = str(e)
        
        return resultado

    @staticmethod
    def teste_udp(alvo: str, porta: int, timeout: int = 3) -> ResultadoTesteConexao:
        """
        Testa conectividade UDP para um alvo:porta.
        """
        resultado = ResultadoTesteConexao(
            alvo=alvo,
            porta=porta,
            protocolo="UDP",
            conectado=False
        )
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            
            inicio = time.time()
            try:
                # UDP é connectionless, mas podemos tentar enviar
                sock.sendto(b"", (alvo, porta))
                resultado.conectado = True
                resultado.tempo_ms = (time.time() - inicio) * 1000
            except Exception as e:
                resultado.erro = str(e)
            finally:
                sock.close()
        
        except Exception as e:
            resultado.erro = str(e)
        
        return resultado

    @staticmethod
    def traceroute(alvo: str, max_hops: int = 30, timeout: int = 10) -> ResultadoTraceroute:
        """
        Executa traceroute para um alvo.
        """
        resultado = ResultadoTraceroute(alvo=alvo)
        
        try:
            cmd = ["tracert", "-h", str(max_hops), "-w", str(timeout * 1000), alvo]
            
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 10,
                creationflags=0x08000000
            )
            
            # Parsear output do traceroute
            # Linhas típicas: "  1   <1 ms   <1 ms   <1 ms  router.local [192.168.1.1]"
            linhas = proc.stdout.split('\n')
            hop_num = 0
            
            for linha in linhas:
                if re.match(r'\s*\d+\s+', linha):
                    hop_num += 1
                    partes = linha.split()
                    
                    # Extrair tempos
                    tempos = []
                    for parte in partes:
                        if 'ms' in parte:
                            tempo_str = parte.replace('ms', '').strip('<>*')
                            try:
                                tempos.append(float(tempo_str))
                            except:
                                pass
                    
                    # Extrair IP/host
                    ip_match = re.search(r'\[?(\d+\.\d+\.\d+\.\d+)\]?', linha)
                    ip = ip_match.group(1) if ip_match else ""
                    
                    # Extrair hostname
                    host_match = re.search(r'([a-zA-Z0-9\.\-]+)\s+\[', linha)
                    host = host_match.group(1) if host_match else ""
                    
                    resultado.hops.append({
                        'hop': hop_num,
                        'host': host,
                        'ip': ip,
                        'tempos_ms': tempos,
                        'tempo_medio_ms': sum(tempos) / len(tempos) if tempos else 0,
                    })
        
        except Exception as e:
            resultado.hops.append({'erro': str(e)})
        
        return resultado

    @staticmethod
    def teste_conectividade_completo(alvo: str = "8.8.8.8") -> Dict[str, Any]:
        """
        Executa bateria completa de testes de conectividade.
        """
        return {
            'ping': DiagnosticoConectividade.ping(alvo).para_dict(),
            'tcp_80': DiagnosticoConectividade.teste_tcp(alvo, 80).para_dict(),
            'tcp_443': DiagnosticoConectividade.teste_tcp(alvo, 443).para_dict(),
            'tcp_53': DiagnosticoConectividade.teste_tcp(alvo, 53).para_dict(),
            'traceroute': DiagnosticoConectividade.traceroute(alvo).para_dict(),
        }
