"""
Módulo orquestrador principal de diagnósticos.
Coordena coleta de dados de todas as camadas e gera relatório completo.
"""

import time
import threading
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Callable

from utils.diagnostico_camada_fisica import DiagnosticoCamadaFisica, InfoCamadaFisica
from utils.diagnostico_ip_config import DiagnosticoIPConfig, ConfiguracaoIP
from utils.diagnostico_subrede import DiagnosticoSubrede, AnalisSubrede
from utils.diagnostico_conectividade import DiagnosticoConectividade, ResultadoPing
from utils.diagnostico_dns import DiagnosticoDNS, DiagnosticoDNSCompleto
from utils.diagnostico_trafego import DiagnosticoTrafego, EstatisticaTrafego
from utils.diagnostico_descoberta import DiscoveriaRede, DispositivoRede
from utils.diagnostico_windows import DiagnosticoWindows, VerificacaoWindows


@dataclass
class RelatorioCompletoDiagnostico:
    """Relatório completo de diagnóstico."""
    timestamp: str
    duracao_segundos: float = 0.0
    
    # Camada Física
    interfaces_fisicas: List[Dict[str, Any]] = field(default_factory=list)
    problemas_fisicos: List[str] = field(default_factory=list)
    
    # Camada IP
    configuracoes_ip: List[Dict[str, Any]] = field(default_factory=list)
    problemas_ip: List[str] = field(default_factory=list)
    
    # Sub-redes
    analises_subrede: List[Dict[str, Any]] = field(default_factory=list)
    problemas_subrede: List[str] = field(default_factory=list)
    
    # Conectividade
    teste_conectividade_google: Dict[str, Any] = field(default_factory=dict)
    teste_conectividade_local: Dict[str, Any] = field(default_factory=dict)
    problemas_conectividade: List[str] = field(default_factory=list)
    
    # DNS
    diagnostico_dns: Dict[str, Any] = field(default_factory=dict)
    problemas_dns: List[str] = field(default_factory=list)
    
    # Tráfego
    estatisticas_trafego: Dict[str, Any] = field(default_factory=dict)
    
    # Descoberta
    dispositivos_rede: List[Dict[str, Any]] = field(default_factory=list)
    
    # Windows
    verificacao_windows: Dict[str, Any] = field(default_factory=dict)
    
    # Resumo
    score_saude: float = 0.0  # 0-100
    resumo_problemas: List[str] = field(default_factory=list)
    resumo_avisos: List[str] = field(default_factory=list)
    recomendacoes: List[str] = field(default_factory=list)
    
    def para_dict(self) -> Dict[str, Any]:
        """Converte para dicionário."""
        return asdict(self)


class DiagnosticoAvancado:
    """Orquestrador principal de diagnósticos avançados."""

    def __init__(self, callback_progresso: Optional[Callable[[str, int], None]] = None):
        """
        Inicializa o diagnóstico.
        
        Args:
            callback_progresso: Função(mensagem, percentual) para atualizar progresso
        """
        self.callback_progresso = callback_progresso

    def _atualizar_progresso(self, mensagem: str, percentual: int):
        """Atualiza callback de progresso."""
        if self.callback_progresso:
            self.callback_progresso(mensagem, percentual)
        print(f"[{percentual}%] {mensagem}")

    def executar_diagnostico_completo(
        self,
        interface_rede: Optional[str] = None,
        duracao_trafego_segundos: int = 10,
        testar_conectividade_remota: bool = True
    ) -> RelatorioCompletoDiagnostico:
        """
        Executa diagnóstico completo de todas as camadas.
        """
        inicio = time.time()
        relatorio = RelatorioCompletoDiagnostico(
            timestamp=datetime.now().isoformat()
        )

        try:
            # ════════════════════════════════════════════════════════════════
            # 1. CAMADA FÍSICA
            # ════════════════════════════════════════════════════════════════
            self._atualizar_progresso("Coletando informações de Camada Física...", 5)
            
            interfaces_fisicas = DiagnosticoCamadaFisica.obter_interfaces_windows()
            relatorio.interfaces_fisicas = [i.para_dict() for i in interfaces_fisicas]
            
            for interface in interfaces_fisicas:
                problemas = DiagnosticoCamadaFisica.validar_configuracao_fisica(interface)
                relatorio.problemas_fisicos.extend(problemas)

            # ════════════════════════════════════════════════════════════════
            # 2. CAMADA IP
            # ════════════════════════════════════════════════════════════════
            self._atualizar_progresso("Coletando configuração IP...", 15)
            
            configs_ip = DiagnosticoIPConfig.obter_configuracao_ip_windows()
            relatorio.configuracoes_ip = [c.para_dict() for c in configs_ip]
            
            for config in configs_ip:
                problemas = DiagnosticoIPConfig.validar_configuracao(config)
                relatorio.problemas_ip.extend(problemas)

            # ════════════════════════════════════════════════════════════════
            # 3. SUB-REDES
            # ════════════════════════════════════════════════════════════════
            self._atualizar_progresso("Analisando sub-redes...", 25)
            
            for config in configs_ip:
                if config.cidr:
                    analise = DiagnosticoSubrede.analisar_cidr(
                        config.cidr,
                        config.gateway_padrao
                    )
                    if analise:
                        relatorio.analises_subrede.append(analise.para_dict())
                        relatorio.problemas_subrede.extend(analise.problemas)

            # ════════════════════════════════════════════════════════════════
            # 4. CONECTIVIDADE LOCAL
            # ════════════════════════════════════════════════════════════════
            self._atualizar_progresso("Testando conectividade local...", 35)
            
            if configs_ip and configs_ip[0].gateway_padrao:
                gateway = configs_ip[0].gateway_padrao
                ping_local = DiagnosticoConectividade.ping(gateway, pacotes=4)
                relatorio.teste_conectividade_local = ping_local.para_dict()
                
                if not ping_local.sucesso:
                    relatorio.problemas_conectividade.append(
                        f"Gateway {gateway} não respondendo"
                    )

            # ════════════════════════════════════════════════════════════════
            # 5. CONECTIVIDADE REMOTA
            # ════════════════════════════════════════════════════════════════
            if testar_conectividade_remota:
                self._atualizar_progresso("Testando conectividade remota...", 45)
                
                ping_google = DiagnosticoConectividade.ping("8.8.8.8", pacotes=4)
                relatorio.teste_conectividade_google = ping_google.para_dict()
                
                if not ping_google.sucesso:
                    relatorio.problemas_conectividade.append(
                        "Sem conectividade com internet (8.8.8.8)"
                    )
                elif ping_google.perda_percentual > 50:
                    relatorio.problemas_conectividade.append(
                        f"Perda de pacotes alta com internet: {ping_google.perda_percentual}%"
                    )

            # ════════════════════════════════════════════════════════════════
            # 6. DNS
            # ════════════════════════════════════════════════════════════════
            self._atualizar_progresso("Testando DNS...", 55)
            
            diag_dns = DiagnosticoDNS.diagnostico_dns_completo()
            relatorio.diagnostico_dns = {
                'servidores': diag_dns.servidores_dns,
                'problemas': diag_dns.problemas,
            }
            relatorio.problemas_dns.extend(diag_dns.problemas)

            # ════════════════════════════════════════════════════════════════
            # 7. TRÁFEGO (se interface especificada)
            # ════════════════════════════════════════════════════════════════
            if interface_rede:
                self._atualizar_progresso(
                    f"Capturando tráfego de {interface_rede}...",
                    65
                )
                
                stats_trafego = DiagnosticoTrafego.capturar_trafego(
                    interface=interface_rede,
                    duracao_segundos=duracao_trafego_segundos
                )
                relatorio.estatisticas_trafego = stats_trafego.para_dict()
            else:
                self._atualizar_progresso("Pulando análise de tráfego (nenhuma interface)", 65)

            # ════════════════════════════════════════════════════════════════
            # 8. DESCOBERTA DE REDE
            # ════════════════════════════════════════════════════════════════
            self._atualizar_progresso("Descobrindo dispositivos na rede...", 75)
            
            dispositivos = DiscoveriaRede.descoberta_completa()
            relatorio.dispositivos_rede = [d.para_dict() for d in dispositivos]

            # ════════════════════════════════════════════════════════════════
            # 9. VERIFICAÇÕES WINDOWS
            # ════════════════════════════════════════════════════════════════
            self._atualizar_progresso("Verificando sistema Windows...", 85)
            
            verif_windows = DiagnosticoWindows.diagnostico_windows_completo()
            relatorio.verificacao_windows = verif_windows.para_dict()
            relatorio.resumo_avisos.extend(verif_windows.avisos)
            relatorio.resumo_problemas.extend(verif_windows.problemas)
            relatorio.recomendacoes.extend(verif_windows.recomendacoes)

            # ════════════════════════════════════════════════════════════════
            # 10. CALCULAR SCORE DE SAÚDE
            # ════════════════════════════════════════════════════════════════
            self._atualizar_progresso("Calculando score de saúde...", 95)
            
            score = 100.0
            
            # Descontar por problemas
            score -= len(relatorio.problemas_fisicos) * 5
            score -= len(relatorio.problemas_ip) * 5
            score -= len(relatorio.problemas_subrede) * 3
            score -= len(relatorio.problemas_conectividade) * 10
            score -= len(relatorio.problemas_dns) * 5
            
            # Descontar por avisos
            score -= len(relatorio.resumo_avisos) * 2
            
            relatorio.score_saude = max(0, min(100, score))
            
            # Adicionar resumo de problemas
            relatorio.resumo_problemas.extend(relatorio.problemas_fisicos)
            relatorio.resumo_problemas.extend(relatorio.problemas_ip)
            relatorio.resumo_problemas.extend(relatorio.problemas_subrede)
            relatorio.resumo_problemas.extend(relatorio.problemas_conectividade)
            relatorio.resumo_problemas.extend(relatorio.problemas_dns)

        except Exception as e:
            relatorio.resumo_problemas.append(f"Erro durante diagnóstico: {str(e)}")

        finally:
            relatorio.duracao_segundos = time.time() - inicio
            self._atualizar_progresso("Diagnóstico concluído!", 100)

        return relatorio

    @staticmethod
    def gerar_relatorio_markdown(relatorio: RelatorioCompletoDiagnostico) -> str:
        """
        Gera relatório em formato Markdown.
        """
        linhas = []
        
        linhas.append("# Relatório de Diagnóstico de Rede - NetLab Educacional")
        linhas.append("")
        linhas.append(f"**Data/Hora:** {relatorio.timestamp}")
        linhas.append(f"**Duração:** {relatorio.duracao_segundos:.1f}s")
        status_saude = "Bom" if relatorio.score_saude >= 80 else "Atenção" if relatorio.score_saude >= 50 else "Crítico"
        linhas.append(f"**Score de Saúde:** {relatorio.score_saude:.0f}% ({status_saude})")
        linhas.append("")
        
        # ════════════════════════════════════════════════════════════════
        # RESUMO EXECUTIVO
        # ════════════════════════════════════════════════════════════════
        linhas.append("## Resumo Executivo")
        linhas.append("")
        
        if relatorio.resumo_problemas:
            linhas.append(f"**Problemas Críticos:** {len(relatorio.resumo_problemas)}")
            for problema in relatorio.resumo_problemas[:5]:
                linhas.append(f"  - {problema}")
            linhas.append("")
        
        if relatorio.resumo_avisos:
            linhas.append(f"**Avisos:** {len(relatorio.resumo_avisos)}")
            for aviso in relatorio.resumo_avisos[:5]:
                linhas.append(f"  - {aviso}")
            linhas.append("")
        
        if relatorio.recomendacoes:
            linhas.append(f"**Recomendações:** {len(relatorio.recomendacoes)}")
            for rec in relatorio.recomendacoes[:5]:
                linhas.append(f"  - {rec}")
            linhas.append("")
        
        # ════════════════════════════════════════════════════════════════
        # CAMADA FÍSICA
        # ════════════════════════════════════════════════════════════════
        if relatorio.interfaces_fisicas:
            linhas.append("## Camada Física (Layer 1)")
            linhas.append("")
            
            for iface in relatorio.interfaces_fisicas:
                linhas.append(f"### {iface['nome_interface']}")
                linhas.append(f"  - **MAC:** {iface['endereco_mac']}")
                linhas.append(f"  - **Descrição:** {iface['descricao']}")
                linhas.append(f"  - **Velocidade:** {iface['velocidade_mbps']} Mbps")
                linhas.append(f"  - **Duplex:** {iface['modo_duplex']}")
                linhas.append(f"  - **Estado:** {iface['estado']}")
                linhas.append(f"  - **MTU:** {iface['mtu']} bytes")
                if iface['erros_crc'] > 0:
                    linhas.append(f"  - **Erros CRC:** {iface['erros_crc']}")
                linhas.append("")
        
        # ════════════════════════════════════════════════════════════════
        # CONFIGURAÇÃO IP
        # ════════════════════════════════════════════════════════════════
        if relatorio.configuracoes_ip:
            linhas.append("## Configuração IP (Layer 3)")
            linhas.append("")
            
            for config in relatorio.configuracoes_ip:
                linhas.append(f"### {config['nome_interface']}")
                linhas.append(f"  - **IPv4:** {config['ipv4']}/{config['mascara_ipv4']}")
                linhas.append(f"  - **CIDR:** {config['cidr']}")
                linhas.append(f"  - **Gateway:** {config['gateway_padrao']}")
                if config['dns_primario']:
                    linhas.append(f"  - **DNS Primário:** {config['dns_primario']}")
                if config['dns_secundario']:
                    linhas.append(f"  - **DNS Secundário:** {config['dns_secundario']}")
                linhas.append(f"  - **DHCP:** {'Ativado' if config['dhcp_ativado'] else 'Desativado'}")
                linhas.append("")
        
        # ════════════════════════════════════════════════════════════════
        # CONECTIVIDADE
        # ════════════════════════════════════════════════════════════════
        linhas.append("## Conectividade")
        linhas.append("")
        
        if relatorio.teste_conectividade_local:
            ping = relatorio.teste_conectividade_local
            linhas.append("### Gateway Local")
            linhas.append(f"  - **Alvo:** {ping['alvo']}")
            linhas.append(f"  - **Status:** {'Respondendo' if ping['sucesso'] else 'Sem resposta'}")
            if ping['sucesso']:
                linhas.append(f"  - **Latência Média:** {ping['tempo_medio']:.1f}ms")
                linhas.append(f"  - **Perda:** {ping['perda_percentual']:.1f}%")
            linhas.append("")
        
        if relatorio.teste_conectividade_google:
            ping = relatorio.teste_conectividade_google
            linhas.append("### Internet (8.8.8.8)")
            linhas.append(f"  - **Status:** {'Conectado' if ping['sucesso'] else 'Sem conectividade'}")
            if ping['sucesso']:
                linhas.append(f"  - **Latência Média:** {ping['tempo_medio']:.1f}ms")
                linhas.append(f"  - **Perda:** {ping['perda_percentual']:.1f}%")
            linhas.append("")
        
        # ════════════════════════════════════════════════════════════════
        # DNS
        # ════════════════════════════════════════════════════════════════
        if relatorio.diagnostico_dns:
            linhas.append("## Diagnóstico DNS")
            linhas.append("")
            
            dns_info = relatorio.diagnostico_dns
            if dns_info.get('servidores'):
                linhas.append(f"**Servidores configurados:**")
                for servidor in dns_info['servidores']:
                    linhas.append(f"  - {servidor}")
                linhas.append("")
        
        # ════════════════════════════════════════════════════════════════
        # DISPOSITIVOS DESCOBERTOS
        # ════════════════════════════════════════════════════════════════
        if relatorio.dispositivos_rede:
            linhas.append("## Dispositivos na Rede")
            linhas.append("")
            linhas.append(f"**Total:** {len(relatorio.dispositivos_rede)} dispositivo(s)")
            linhas.append("")
            
            for disp in relatorio.dispositivos_rede[:10]:
                linhas.append(f"  - {disp['ip']} ({disp['mac']}) {disp['hostname']}")
        
        # ════════════════════════════════════════════════════════════════
        # WINDOWS
        # ════════════════════════════════════════════════════════════════
        if relatorio.verificacao_windows:
            linhas.append("## Verificações Windows")
            linhas.append("")
            
            win = relatorio.verificacao_windows
            linhas.append(f"  - **Firewall:** {'Ativado' if win['firewall_ativado'] else 'Desativado'}")
            linhas.append(f"  - **Defender:** {'Ativado' if win['defender_ativado'] else 'Desativado'}")
            linhas.append(f"  - **Winsock:** {'OK' if win['winsock_ok'] else 'Problema'}")
            linhas.append(f"  - **Drivers NDIS:** {'OK' if win['drivers_ndis_ok'] else 'Problema'}")
            linhas.append(f"  - **VPN:** {'Ativa' if win['vpn_detectada'] else 'Desativa'}")
            linhas.append("")
        
        return "\n".join(linhas)

    @staticmethod
    def gerar_relatorio_html(relatorio: RelatorioCompletoDiagnostico) -> str:
        """
        Gera relatório em formato HTML.
        """
        # Este é um método auxiliar; a UI será responsável pela renderização
        return DiagnosticoAvancado.gerar_relatorio_markdown(relatorio)
