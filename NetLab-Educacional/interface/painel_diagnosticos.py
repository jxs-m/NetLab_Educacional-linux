"""
Painel de Diagnósticos Avançados - Interface PyQt6
Exibe relatório completo de diagnóstico de rede em formato estruturado.
"""

import threading
import time
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QProgressBar, QTextBrowser, QScrollArea, QFrame,
    QSplitter, QComboBox, QSpinBox, QCheckBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
from PyQt6.QtGui import QColor, QFont
from html import escape

from utils.diagnostico_avancado import DiagnosticoAvancado, RelatorioCompletoDiagnostico


class _WorkerDiagnostico(QThread):
    """Worker thread para executar diagnósticos sem bloquear UI."""
    progresso = pyqtSignal(str, int)  # mensagem, percentual
    conclusao = pyqtSignal(object)  # RelatorioCompletoDiagnostico
    erro = pyqtSignal(str)
    
    def __init__(self, interface_rede=None, duracao_trafego=10, teste_remoto=True):
        super().__init__()
        self.interface_rede = interface_rede
        self.duracao_trafego = duracao_trafego
        self.teste_remoto = teste_remoto

    def run(self):
        """Executa diagnóstico em thread separada."""
        try:
            diagnostico = DiagnosticoAvancado(
                callback_progresso=self._callback_progresso
            )
            
            relatorio = diagnostico.executar_diagnostico_completo(
                interface_rede=self.interface_rede,
                duracao_trafego_segundos=self.duracao_trafego,
                testar_conectividade_remota=self.teste_remoto
            )
            
            self.conclusao.emit(relatorio)
        
        except Exception as e:
            self.erro.emit(f"Erro durante diagnóstico: {str(e)}")

    def _callback_progresso(self, mensagem: str, percentual: int):
        """Callback para atualizar progresso."""
        self.progresso.emit(mensagem, percentual)


class PainelDiagnosticos(QWidget):
    """Painel completo de diagnósticos de rede."""
    
    # ═══════════════════════════════════════════════════════════════════
    # DESIGN TOKENS — Paleta NetLab Educacional
    # ═══════════════════════════════════════════════════════════════════
    
    _BG        = "#090d18"
    _BG2       = "#0d1120"
    _SURFACE   = "#0f1422"
    _SURFACE2  = "#131828"
    _CARD      = "#0b0f1e"
    _BORDA     = "#182038"
    _BORDA2    = "#1f2e4a"
    _SEL       = "#152f4e"
    _ACCENT    = "#3a9ecf"
    _ACCENT2   = "#57b2e2"
    _TEXTO     = "#d8e4f0"
    _TEXTO2    = "#a6bccb"
    _MUTED     = "#5f7489"
    _DIM       = "#354e63"
    
    _CRITICO   = "#de4f4f"
    _AVISO     = "#cf832a"
    _SUCESSO   = "#4a9d6f"
    _INFO      = "#3a9ecf"
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.relatorio_atual = None
        self.worker = None
        self._inicializar_ui()

    def _inicializar_ui(self):
        """Inicializa interface de diagnóstico."""
        layout_principal = QVBoxLayout(self)
        layout_principal.setContentsMargins(0, 0, 0, 0)
        layout_principal.setSpacing(0)
        
        # ═══════════════════════════════════════════════════════════════
        # SEÇÃO DE CONTROLES
        # ═══════════════════════════════════════════════════════════════
        
        layout_controles = QHBoxLayout()
        layout_controles.setContentsMargins(12, 10, 12, 10)
        layout_controles.setSpacing(8)
        
        # Botão Iniciar
        self.btn_iniciar = QPushButton("Iniciar Diagnóstico")
        self.btn_iniciar.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_iniciar.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.btn_iniciar.setMinimumHeight(36)
        self.btn_iniciar.setStyleSheet(f"""
            QPushButton {{
                background: {self._ACCENT};
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }}
            QPushButton:hover {{ background: {self._ACCENT2}; }}
            QPushButton:pressed {{ background: #2a7db8; }}
            QPushButton:disabled {{ background: {self._MUTED}; color: {self._TEXTO2}; }}
        """)
        self.btn_iniciar.clicked.connect(self._iniciar_diagnostico)
        
        # Opções
        lbl_interface = QLabel("Interface:")
        lbl_interface.setStyleSheet(f"color: {self._TEXTO};")
        self.combo_interface = QComboBox()
        self.combo_interface.setStyleSheet(f"""
            QComboBox {{
                background: {self._SURFACE};
                color: {self._TEXTO};
                border: 1px solid {self._BORDA};
                border-radius: 4px;
                padding: 4px;
            }}
        """)
        self.combo_interface.addItems(["Nenhuma (Física apenas)", "eth0", "wlan0"])
        
        lbl_duracao = QLabel("Tráfego (s):")
        lbl_duracao.setStyleSheet(f"color: {self._TEXTO};")
        self.spin_duracao = QSpinBox()
        self.spin_duracao.setMinimum(5)
        self.spin_duracao.setMaximum(60)
        self.spin_duracao.setValue(10)
        self.spin_duracao.setStyleSheet(f"""
            QSpinBox {{
                background: {self._SURFACE};
                color: {self._TEXTO};
                border: 1px solid {self._BORDA};
                border-radius: 4px;
                padding: 4px;
            }}
        """)
        
        self.chk_remoto = QCheckBox("Teste remoto")
        self.chk_remoto.setChecked(True)
        self.chk_remoto.setStyleSheet(f"color: {self._TEXTO};")
        
        layout_controles.addWidget(self.btn_iniciar)
        layout_controles.addWidget(lbl_interface)
        layout_controles.addWidget(self.combo_interface)
        layout_controles.addWidget(lbl_duracao)
        layout_controles.addWidget(self.spin_duracao)
        layout_controles.addWidget(self.chk_remoto)
        layout_controles.addStretch()
        
        frame_controles = QFrame()
        frame_controles.setStyleSheet(f"""
            QFrame {{
                background: {self._SURFACE};
                border-bottom: 1px solid {self._BORDA};
            }}
        """)
        frame_controles.setLayout(layout_controles)
        
        # ═══════════════════════════════════════════════════════════════
        # BARRA DE PROGRESSO
        # ═══════════════════════════════════════════════════════════════
        
        layout_progress = QVBoxLayout()
        layout_progress.setContentsMargins(12, 8, 12, 8)
        layout_progress.setSpacing(4)
        
        self.lbl_status = QLabel("")
        self.lbl_status.setStyleSheet(f"color: {self._TEXTO2};")
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                background: {self._CARD};
                border: 1px solid {self._BORDA};
                border-radius: 4px;
                text-align: center;
                color: {self._TEXTO};
            }}
            QProgressBar::chunk {{
                background: {self._ACCENT};
                border-radius: 3px;
            }}
        """)
        self.progress_bar.setVisible(False)
        
        layout_progress.addWidget(self.lbl_status)
        layout_progress.addWidget(self.progress_bar)
        
        frame_progress = QFrame()
        frame_progress.setStyleSheet(f"background: {self._SURFACE};")
        frame_progress.setLayout(layout_progress)
        frame_progress.setVisible(False)
        self.frame_progress = frame_progress
        
        # ═══════════════════════════════════════════════════════════════
        # ÁREA DE EXIBIÇÃO
        # ═══════════════════════════════════════════════════════════════
        
        self.text_relatorio = QTextBrowser()
        self.text_relatorio.setStyleSheet(f"""
            QTextBrowser {{
                background: {self._BG};
                color: {self._TEXTO};
                border: none;
                padding: 12px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 9pt;
            }}
            QTextBrowser:hover {{ background: {self._BG}; }}
        """)
        
        # ═══════════════════════════════════════════════════════════════
        # MONTAGEM FINAL
        # ═══════════════════════════════════════════════════════════════
        
        layout_principal.addWidget(frame_controles)
        layout_principal.addWidget(frame_progress)
        layout_principal.addWidget(self.text_relatorio)

    def _iniciar_diagnostico(self):
        """Inicia execução do diagnóstico."""
        if self.worker and self.worker.isRunning():
            # Se já está rodando, abortar
            self.worker.terminate()
            self.btn_iniciar.setText("Iniciar Diagnóstico")
            self.frame_progress.setVisible(False)
            return
        
        # Desabilitar controles
        self.btn_iniciar.setEnabled(False)
        self.combo_interface.setEnabled(False)
        self.spin_duracao.setEnabled(False)
        self.chk_remoto.setEnabled(False)
        self.btn_iniciar.setText("Cancelar")
        self.frame_progress.setVisible(True)
        self.progress_bar.setValue(0)
        self.lbl_status.setText("Iniciando diagnóstico...")
        
        # Criar e iniciar worker
        interface = None
        if self.combo_interface.currentIndex() > 0:
            interface = self.combo_interface.currentText()
        
        self.worker = _WorkerDiagnostico(
            interface_rede=interface,
            duracao_trafego=self.spin_duracao.value(),
            teste_remoto=self.chk_remoto.isChecked()
        )
        
        self.worker.progresso.connect(self._atualizar_progresso)
        self.worker.conclusao.connect(self._diagnostico_concluido)
        self.worker.erro.connect(self._diagnostico_erro)
        self.worker.start()

    def _atualizar_progresso(self, mensagem: str, percentual: int):
        """Atualiza barra de progresso."""
        self.lbl_status.setText(mensagem)
        self.progress_bar.setValue(percentual)

    def _diagnostico_concluido(self, relatorio: RelatorioCompletoDiagnostico):
        """Diagnóstico completado com sucesso."""
        self.relatorio_atual = relatorio
        self._exibir_relatorio(relatorio)
        
        # Reabilitar controles
        self.btn_iniciar.setEnabled(True)
        self.combo_interface.setEnabled(True)
        self.spin_duracao.setEnabled(True)
        self.chk_remoto.setEnabled(True)
        self.btn_iniciar.setText("Novo Diagnóstico")
        
        QTimer.singleShot(2000, lambda: self.frame_progress.setVisible(False))

    def _diagnostico_erro(self, erro: str):
        """Erro durante diagnóstico."""
        self.text_relatorio.setHtml(f"""
            <div style="color: {self._CRITICO}; font-weight: bold; padding: 20px;">
                <h2>Erro ao executar diagnóstico</h2>
                <p>{escape(erro)}</p>
                <p style="font-size: 0.9em; color: {self._TEXTO2};">
                    Verifique se tem privilégios de administrador.
                </p>
            </div>
        """)
        
        # Reabilitar controles
        self.btn_iniciar.setEnabled(True)
        self.combo_interface.setEnabled(True)
        self.spin_duracao.setEnabled(True)
        self.chk_remoto.setEnabled(True)
        self.btn_iniciar.setText("Iniciar Diagnóstico")
        self.frame_progress.setVisible(False)

    def _exibir_relatorio(self, relatorio: RelatorioCompletoDiagnostico):
        """Exibe relatório em HTML formatado."""
        html = self._gerar_html_relatorio(relatorio)
        self.text_relatorio.setHtml(html)

    def _gerar_html_relatorio(self, relatorio: RelatorioCompletoDiagnostico) -> str:
        """Gera HTML do relatório."""
        linhas = []
        
        # Cabeçalho
        cor_score = self._SUCESSO if relatorio.score_saude >= 80 else (
            self._AVISO if relatorio.score_saude >= 50 else self._CRITICO
        )
        
        linhas.append(f"""
            <div style="padding: 20px; background: {self._SURFACE}; border-bottom: 1px solid {self._BORDA};">
                <h1 style="margin: 0; color: {self._ACCENT};">Diagnóstico de Rede</h1>
                <p style="margin: 8px 0 0 0; color: {self._TEXTO2};">
                    Duração: <strong>{relatorio.duracao_segundos:.1f}s</strong> | 
                    Score: <span style="color: {cor_score}; font-weight: bold;">{relatorio.score_saude:.0f}%</span>
                </p>
            </div>
        """)
        
        # Resumo de Problemas
        if relatorio.resumo_problemas or relatorio.resumo_avisos:
            linhas.append(f"""
                <div style="padding: 12px; background: {self._CARD}; margin: 12px;">
                    <h2 style="color: {self._AVISO}; margin-top: 0;">Resumo</h2>
            """)
            
            if relatorio.resumo_problemas:
                linhas.append(f"<p style=\"color: {self._CRITICO};\"><strong>{len(relatorio.resumo_problemas)} Problema(s) Crítico(s)</strong></p>")
                linhas.append("<ul>")
                for problema in relatorio.resumo_problemas[:5]:
                    linhas.append(f"<li style=\"color: {self._TEXTO};\">{escape(problema)}</li>")
                linhas.append("</ul>")
            
            if relatorio.resumo_avisos:
                linhas.append(f"<p style=\"color: {self._AVISO};\"><strong>{len(relatorio.resumo_avisos)} Aviso(s)</strong></p>")
                linhas.append("<ul>")
                for aviso in relatorio.resumo_avisos[:3]:
                    linhas.append(f"<li style=\"color: {self._TEXTO};\">{escape(aviso)}</li>")
                linhas.append("</ul>")
            
            linhas.append("</div>")
        
        # Camada Física
        if relatorio.interfaces_fisicas:
            linhas.append(f"""
                <div style="padding: 12px; margin: 12px;">
                    <h2 style="color: {self._ACCENT};;">Camada Física</h2>
            """)
            
            for iface in relatorio.interfaces_fisicas:
                cor_estado = self._SUCESSO if iface['estado'].lower() == 'up' else self._CRITICO
                linhas.append(f"""
                    <div style="background: {self._SURFACE2}; padding: 8px; margin: 8px 0; border-left: 3px solid {self._ACCENT}; border-radius: 2px;">
                        <p style="margin: 4px 0;"><strong>{iface['nome_interface']}</strong> 
                        <span style="color: {cor_estado};">[{iface['estado']}]</span></p>
                        <p style="margin: 4px 0; font-size: 0.9em; color: {self._TEXTO2};">
                            MAC: {iface['endereco_mac']} | 
                            Velocidade: {iface['velocidade_mbps']} Mbps | 
                            {iface['modo_duplex']}
                        </p>
                    </div>
                """)
            
            linhas.append("</div>")
        
        # Configuração IP
        if relatorio.configuracoes_ip:
            linhas.append(f"""
                <div style="padding: 12px; margin: 12px;">
                    <h2 style="color: {self._ACCENT};">Configuração IP</h2>
            """)
            
            for config in relatorio.configuracoes_ip:
                linhas.append(f"""
                    <div style="background: {self._SURFACE2}; padding: 8px; margin: 8px 0; border-left: 3px solid {self._INFO}; border-radius: 2px;">
                        <p style="margin: 4px 0;"><strong>{config['nome_interface']}</strong></p>
                        <p style="margin: 4px 0; font-family: monospace; font-size: 0.9em; color: {self._TEXTO};">
                            IPv4: {config['ipv4']}/{config['mascara_ipv4']}<br/>
                            Gateway: {config['gateway_padrao']}<br/>
                            DNS: {config['dns_primario']}
                        </p>
                        <p style="margin: 4px 0; font-size: 0.85em; color: {self._TEXTO2};">
                            DHCP: {'Sim' if config['dhcp_ativado'] else 'Não'}
                        </p>
                    </div>
                """)
            
            linhas.append("</div>")
        
        # Conectividade
        linhas.append(f"""
            <div style="padding: 12px; margin: 12px;">
                <h2 style="color: {self._ACCENT};">Conectividade</h2>
        """)
        
        if relatorio.teste_conectividade_local and relatorio.teste_conectividade_local.get('sucesso'):
            ping = relatorio.teste_conectividade_local
            linhas.append(f"""
                <div style="background: {self._SURFACE2}; padding: 8px; margin: 8px 0; border-radius: 2px;">
                    <p style="margin: 4px 0;"><strong>Gateway Local:</strong> 
                    <span style="color: {self._SUCESSO};">Respondendo</span></p>
                    <p style="margin: 4px 0; font-size: 0.9em; color: {self._TEXTO2};">
                        Latência: {ping['tempo_medio']:.1f}ms | Perda: {ping['perda_percentual']:.1f}%
                    </p>
                </div>
            """)
        
        if relatorio.teste_conectividade_google:
            ping = relatorio.teste_conectividade_google
            cor = self._SUCESSO if ping['sucesso'] else self._CRITICO
            status = "Conectado" if ping['sucesso'] else "Sem conectividade"
            linhas.append(f"""
                <div style="background: {self._SURFACE2}; padding: 8px; margin: 8px 0; border-radius: 2px;">
                    <p style="margin: 4px 0;"><strong>Internet (8.8.8.8):</strong> 
                    <span style="color: {cor};">{status}</span></p>
                    {'<p style="margin: 4px 0; font-size: 0.9em; color: ' + self._TEXTO2 + ';">Latência: ' + str(round(ping["tempo_medio"], 1)) + 'ms | Perda: ' + str(round(ping["perda_percentual"], 1)) + '%</p>' if ping['sucesso'] else ''}
                </div>
            """)
        
        linhas.append("</div>")
        
        # Windows
        if relatorio.verificacao_windows:
            win = relatorio.verificacao_windows
            linhas.append(f"""
                <div style="padding: 12px; margin: 12px;">
                    <h2 style="color: {self._ACCENT};">Sistema Windows</h2>
                    <div style="background: {self._SURFACE2}; padding: 12px; border-radius: 2px;">
                        <p>Firewall: <span style="color: {self._SUCESSO if win['firewall_ativado'] else self._AVISO};">{'Ativado' if win['firewall_ativado'] else 'Desativado'}</span></p>
                        <p>Defender: <span style="color: {self._SUCESSO if win['defender_ativado'] else self._AVISO};">{'Ativado' if win['defender_ativado'] else 'Desativado'}</span></p>
                        <p>Winsock: <span style="color: {self._SUCESSO if win['winsock_ok'] else self._CRITICO};">{'OK' if win['winsock_ok'] else 'Problema'}</span></p>
                    </div>
                </div>
            """)
        
        linhas.append("</div>")
        
        return "\n".join(linhas)
