"""
interface/conteudo_manual.py
────────────────────────────
Conteúdo HTML e CSS para o Manual de Uso do NetLab Educacional.
"""

CSS_MANUAL = """
<style>
  body  { font-family:'Segoe UI',Arial,sans-serif;
          color:#ecf0f1; background:#0a0e1a;
          font-size:11px; line-height:1.65; margin:0; padding:0; }
  h2    { color:#ecf0f1; font-size:15px; margin:0 0 4px 0; }
  h3    { color:#cbd5e1; font-size:12px; margin:14px 0 4px 0; }
  h4    { color:#d1d5db; font-size:11px; margin:10px 0 2px 0; }
  b     { color:#ecf0f1; }
  code  { background:#111827; color:#3d9fd3;
          padding:1px 5px; border-radius:3px;
          font-family:Consolas,monospace; font-size:10px; }
  .muted{ color:#8792a2; font-size:10px; }
  .ok   { color:#2ecc71; font-weight:bold; }
  .warn { color:#e67e22; font-weight:bold; }
  .crit { color:#e74c3c; font-weight:bold; }
  .info { color:#3d9fd3; font-weight:bold; }
  .pill { display:inline-block; padding:1px 7px; border-radius:10px;
          font-size:9px; font-weight:bold; font-family:Consolas,monospace; }
  .p-http,
  .p-https,
  .p-dns,
  .p-arp,
  .p-etc   { background:#17202b; color:#ecf0f1; border:1px solid #2a3038; }
  table { border-collapse:collapse; width:100%; margin:6px 0; font-size:10px; }
  th    { background:#111827; color:#a7b0bd; padding:5px 10px;
          text-align:left; border:1px solid #2a3038; }
  td    { padding:5px 10px; border:1px solid #2a3038; color:#ecf0f1; }
  tr:nth-child(even) td { background:#111827; }
  .box  { background:#111827; border:1px solid #1f2937;
          border-radius:6px; padding:10px 14px; margin:8px 0; }
  .box-warn { background:#1b140a; border:1px solid #e67e22;
              border-radius:6px; padding:10px 14px; margin:8px 0; }
  .box-ok   { background:#0a1a0f; border:1px solid #2ecc71;
              border-radius:6px; padding:10px 14px; margin:8px 0; }
  ul { margin:4px 0 8px 0; padding-left:18px; }
  li { margin:3px 0; }
  hr { border:0; height:1px; background:#2a3038; color:#2a3038; margin:14px 0; }
</style>
"""

CONTEUDO_MANUAL: dict[str, str] = {
    "req": """<h2>Requisitos do Sistema</h2>

<div class="box-ok">
  <b>✓ Sistema Operacional:</b> Windows 10/11 (64 bits) – o NetLab foi projetado para Windows,
  utilizando Npcap e Scapy com suporte nativo à captura de pacotes.
</div>

<h3>Dependências Obrigatórias</h3>
<ul>
  <li><b>Python 3.11 ou superior</b> – o NetLab é executado em Python puro.</li>
  <li><b>Npcap</b> – driver de captura de pacotes (<span class="info">obrigatório</span>).
    Baixe em <a href="https://npcap.com" style="color:#3d9fd3;">npcap.com</a>
    e instale com a opção <b>"WinPcap API-compatible mode"</b> marcada.</li>
  <li><b>Scapy</b> – biblioteca para manipulação de pacotes (<code>pip install scapy</code>).</li>
  <li><b>PyQt6</b> – interface gráfica (<code>pip install PyQt6</code>).</li>
  <li><b>PyQtGraph</b> – gráficos em tempo real (<code>pip install pyqtgraph</code>).</li>
</ul>

<h3>Dependências Opcionais</h3>
<ul>
  <li><b>psutil</b> – estatísticas de interface.</li>
  <li><b>netifaces</b> – detecção alternativa de interfaces.</li>
  <li><b>manuf</b> – identificação de fabricantes por OUI.</li>
</ul>

<h3>Privilégios</h3>
<div class="box-warn">
  <span class="warn">⚠ A captura de pacotes no Windows pode exigir privilégios de Administrador.</span><br>
  Execute o NetLab como administrador para garantir o funcionamento completo.
</div>

<h3>Espaço em Disco</h3>
<ul>
  <li>O NetLab mantém dados de tráfego em memória conforme os limites configurados.</li>
  <li>A escrita em disco ocorre principalmente durante exportações e salvamento de configurações.</li>
</ul>

<div class="box">
  <b>Verificação rápida:</b> execute
  <code>python -c "from scapy.all import *; print('Scapy OK')"</code>.
</div>""",

    "inicio": """<h2>Início Rápido – Primeiros Passos</h2>

<div class="box-ok">
  <b>✓ Objetivo:</b> iniciar a captura, visualizar a topologia e acompanhar o tráfego da rede.
</div>

<h3>Passo a Passo</h3>
<ol>
  <li><b>Execute como Administrador</b>, quando necessário para captura de pacotes.</li>
  <li><b>Selecione a interface de rede</b> no campo "Interface:".</li>
  <li><b>Inicie a captura</b> usando o botão <span class="pill">Iniciar Captura</span> ou o atalho configurado.</li>
  <li><b>Observe a topologia</b> na aba <b>Topologia da Rede</b>.</li>
  <li><b>Acompanhe o tráfego</b> na aba <b>Tráfego em Tempo Real</b>.</li>
  <li><b>Analise eventos</b> no <b>Modo Análise</b>.</li>
</ol>

<h3>Interações Básicas</h3>
<ul>
  <li><b>Gráfico:</b> use os controles disponíveis para navegar e analisar o histórico.</li>
  <li><b>Topologia:</b> selecione dispositivos para visualizar informações e opções disponíveis.</li>
  <li><b>Modo Análise:</b> utilize a busca e os filtros para localizar eventos.</li>
</ul>

<div class="box-warn">
  <span class="warn">⚠ Se a captura não iniciar:</span>
  verifique Npcap, privilégios e a interface selecionada.
</div>""",

    "iface": """<h2>Interface de Rede – Escolha e Configuração</h2>

<p>
  O NetLab utiliza a interface selecionada para capturar e analisar o tráfego disponível
  para o sistema operacional.
</p>

<h3>Como selecionar</h3>
<ul>
  <li>O campo <b>"Interface:"</b> lista as interfaces detectadas.</li>
  <li>O IP local é mostrado para facilitar a identificação.</li>
  <li>Em máquinas com Ethernet e Wi-Fi, selecione a interface conectada à rede desejada.</li>
</ul>

<h3>Ethernet e Wi-Fi</h3>
<ul>
  <li><b>Ethernet:</b> normalmente oferece maior previsibilidade para captura de tráfego local.</li>
  <li><b>Wi-Fi:</b> a capacidade de observar tráfego de outros dispositivos depende do adaptador,
  driver, modo de operação e arquitetura da rede.</li>
</ul>

<h3>CIDR e Gateway</h3>
<p>
  O NetLab utiliza informações da interface para determinar a rede local e identificar o gateway.
</p>

<div class="box">
  <b>Dica:</b> caso o projeto disponibilize configuração manual de rede,
  utilize as opções existentes em <b>Monitoramento → Configurações</b>.
</div>

<h3>Problemas Comuns</h3>
<ul>
  <li><span class="crit">Nenhuma interface:</span> verifique drivers, Npcap e permissões.</li>
  <li><span class="warn">IP 169.254.x.x:</span> normalmente indica ausência de configuração DHCP válida.</li>
  <li><span class="warn">Adaptador não reconhecido:</span> verifique a instalação do Npcap.</li>
</ul>""",

    "topo": """<h2>Topologia da Rede – Visualização Interativa</h2>

<p>
  A topologia representa os dispositivos identificados pelo NetLab e suas relações
  observadas durante o monitoramento.
</p>

<h3>Cores dos Nós</h3>
<ul>
  <li><span style="color:#2ecc71;">●</span> <b>Verde:</b> computador local.</li>
  <li><span style="color:#e74c3c;">●</span> <b>Vermelho:</b> gateway/roteador.</li>
  <li><span style="color:#3498db;">●</span> <b>Azul:</b> dispositivos locais.</li>
  <li><span style="color:#9b59b6;">●</span> <b>Roxo:</b> Internet ou agrupamento externo.</li>
  <li><span style="color:#f39c12;">●</span> <b>Laranja:</b> host adicionado manualmente.</li>
</ul>

<h3>Interações</h3>
<ul>
  <li><b>Zoom:</b> utilize a roda do mouse.</li>
  <li><b>Pan:</b> arraste o canvas conforme suportado pela interface.</li>
  <li><b>Clique esquerdo:</b> seleciona um dispositivo.</li>
  <li><b>Duplo clique:</b> permite definir o apelido quando essa função estiver disponível.</li>
  <li><b>Botão direito:</b> abre o menu de contexto do dispositivo.</li>
</ul>

<h3>Gerenciamento de Hosts</h3>
<ul>
  <li><b>Definir Apelido:</b> identifica o dispositivo com um nome personalizado.</li>
  <li><b>Copiar IP:</b> copia o endereço IP.</li>
  <li><b>Remover da Topologia:</b> remove o dispositivo conforme o comportamento atual do projeto.</li>
  <li><b>Filtro de exclusão:</b> impede a exibição de dispositivos configurados para exclusão.</li>
  <li><b>Host manual:</b> permite adicionar um dispositivo manualmente quando essa função existir.</li>
</ul>

<div class="box-warn">
  <span class="warn">⚠ Limitação:</span>
  a quantidade e precisão dos dispositivos detectados dependem da arquitetura da rede,
  da interface utilizada e das informações disponíveis ao sistema.
</div>""",

    "trafego": """<h2>Tráfego em Tempo Real – Monitoramento Visual</h2>

<p>
  Esta aba apresenta informações sobre o tráfego observado durante a captura,
  incluindo gráficos, protocolos e dispositivos ativos.
</p>

<h3>Gráfico de Tráfego</h3>
<ul>
  <li><b>Tráfego bruto:</b> representa a variação observada ao longo do tempo.</li>
  <li><b>EMA:</b> suaviza a série temporal para facilitar a visualização da tendência,
      quando disponível.</li>
  <li><b>Crosshair:</b> auxilia na leitura de valores no gráfico, quando disponível.</li>
</ul>

<h3>Navegação Temporal</h3>
<p>
  Utilize os controles existentes abaixo do gráfico para navegar pelo histórico disponível.
</p>

<ul>
  <li>Retroceder no histórico.</li>
  <li>Avançar no histórico.</li>
  <li>Pausar a visualização.</li>
  <li>Retornar ao modo <b>Ao Vivo</b>.</li>
</ul>

<div class="box-ok">
  <b>✓ Dica:</b> navegar pelo histórico não significa necessariamente interromper a captura.
</div>

<h3>Tabelas</h3>
<ul>
  <li><b>Protocolos:</b> apresenta informações agregadas por protocolo.</li>
  <li><b>Dispositivos:</b> permite identificar hosts com maior atividade observada.</li>
</ul>""",

    "analise": """<h2>Modo Análise – Aprendizado Contextual</h2>

<p>
  O Modo Análise transforma informações capturadas em eventos contextualizados,
  facilitando a interpretação dos protocolos e comportamentos observados.
</p>

<h3>Eventos</h3>
<ul>
  <li>Os eventos são organizados cronologicamente.</li>
  <li>Cada evento apresenta informações como protocolo, origem, destino e horário.</li>
  <li>Badges podem identificar protocolos como HTTPS, HTTP, DNS e ARP.</li>
  <li>Eventos podem possuir níveis como <span class="info">INFO</span>,
      <span class="warn">AVISO</span> e <span class="crit">CRÍTICO</span>.</li>
</ul>

<h3>Filtros e Busca</h3>
<ul>
  <li>Filtre eventos por protocolo.</li>
  <li>Utilize a busca para localizar IPs, domínios, protocolos ou termos específicos.</li>
</ul>

<h3>Detalhes do Evento</h3>
<ul>
  <li><b>Análise:</b> explicação contextual do evento.</li>
  <li><b>Evidências:</b> informações técnicas disponíveis no pacote.</li>
  <li><b>Na Prática:</b> contextualização pedagógica e relação com situações reais.</li>
</ul>

<h3>Glossário</h3>
<p>
  Quando disponível, termos técnicos podem ser consultados diretamente pelo glossário
  contextual da aplicação.
</p>

<div class="box-ok">
  <b>✓ Dica pedagógica:</b> utilize os eventos para relacionar protocolos,
  comportamento de rede e conceitos de segurança.
</div>""",

    "servidor": """<h2>Servidor Lab – Ambiente Educacional de Teste</h2>

<p>
  O NetLab inclui um servidor HTTP destinado a demonstrações educacionais de
  vulnerabilidades e conceitos de segurança.
</p>

<h3>Como usar</h3>
<ul>
  <li>Abra a aba <b>Servidor</b>.</li>
  <li>Inicie o servidor pelo controle disponível na interface.</li>
  <li>Utilize a porta configurada pelo aplicativo.</li>
  <li>Acesse o servidor pelo endereço local indicado pela aplicação.</li>
</ul>

<h3>Endpoints Educacionais</h3>
<ul>
  <li><b>/</b> – página inicial.</li>
  <li><b>/login</b> – demonstração de autenticação.</li>
  <li><b>/search</b> – demonstração de busca.</li>
  <li><b>/profile?user=ID</b> – demonstração de controle de acesso.</li>
  <li><b>/admin</b> – demonstração de área administrativa.</li>
  <li><b>/upload</b> – demonstração de upload.</li>
</ul>

<h3>Exemplos Educacionais</h3>
<ul>
  <li><b>SQL Injection:</b> demonstração de entrada maliciosa em consultas.</li>
  <li><b>XSS:</b> <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
  <li><b>IDOR:</b> alteração de identificadores para demonstrar falhas de autorização.</li>
  <li><b>Força Bruta:</b> demonstração de tentativas repetidas de autenticação.</li>
</ul>

<div class="box-warn">
  <span class="warn">⚠ Atenção:</span>
  este servidor existe exclusivamente para fins educacionais.
  <b>Nunca o exponha à internet nem utilize o ambiente em produção.</b>
</div>""",

    "diag": """<h2>Diagnóstico do Sistema – Solução de Problemas</h2>

<p>
  O diagnóstico verifica componentes relevantes para o funcionamento do NetLab
  e apresenta informações que ajudam a identificar problemas.
</p>

<h3>Verificações</h3>
<ul>
  <li>Privilégios do processo.</li>
  <li>Npcap e componentes relacionados à captura.</li>
  <li>Scapy e dependências.</li>
  <li>Interface de rede, IP, máscara e gateway.</li>
  <li>Conectividade e resolução DNS, quando suportadas.</li>
  <li>Informações de Wi-Fi, quando disponíveis.</li>
  <li>Informações relevantes do Windows e dos drivers.</li>
  <li>Dispositivos detectados pela aplicação.</li>
</ul>

<h3>Como executar</h3>
<ul>
  <li>Abra a ferramenta <b>Diagnóstico</b>.</li>
  <li>Aguarde a conclusão das verificações.</li>
  <li>Analise os indicadores apresentados.</li>
  <li>Exporte o relatório quando essa opção estiver disponível.</li>
</ul>

<h3>Interpretação</h3>
<ul>
  <li><span class="ok">Verde:</span> funcionamento esperado.</li>
  <li><span class="warn">Amarelo:</span> limitação ou situação que merece atenção.</li>
  <li><span class="crit">Vermelho:</span> problema que pode comprometer alguma funcionalidade.</li>
</ul>

<div class="box">
  <b>Dica:</b> execute o diagnóstico antes de investigar manualmente
  problemas relacionados à captura.
</div>""",

    "problems": """<h2>Problemas Comuns e Soluções</h2>

<h3>1. Captura não inicia</h3>
<div class="box">
  <b>Verifique:</b> Npcap, permissões, interface selecionada e estado da conexão.
</div>

<h3>2. Nenhum pacote capturado</h3>
<div class="box">
  <b>Possíveis causas:</b> interface incorreta, ausência de tráfego,
  limitações do adaptador ou configuração de captura.
</div>

<h3>3. Topologia vazia</h3>
<div class="box">
  <b>Possíveis causas:</b> ausência de dados suficientes para identificar hosts,
  interface incorreta ou filtros de exclusão.
</div>

<h3>4. Servidor não inicia</h3>
<div class="box">
  <b>Possível causa:</b> a porta configurada já está sendo utilizada por outro processo.
  Verifique a configuração do servidor.
</div>

<h3>5. Falha na resolução DNS</h3>
<div class="box">
  <b>Possíveis causas:</b> ausência de conectividade, DNS indisponível
  ou bloqueios específicos da rede.
</div>

<h3>6. Drops ou erros</h3>
<div class="box">
  <b>Possíveis causas:</b> alto volume de tráfego, limitações do driver,
  interface sobrecarregada ou configuração inadequada.
</div>""",

    "dicas": """<h2>Dicas Avançadas para Uso em Sala de Aula</h2>

<div class="box-ok">
  <b>✓ Personalização:</b> utilize apelidos para identificar dispositivos
  de maneira mais fácil durante as demonstrações.
</div>

<h3>Configurações Avançadas</h3>
<p>
  Utilize <b>Monitoramento → Configurações</b> para ajustar as opções realmente
  disponibilizadas pela versão atual do NetLab.
</p>

<ul>
  <li>Limite de dispositivos.</li>
  <li>Intervalo de redescoberta.</li>
  <li>Timeouts relacionados à descoberta.</li>
  <li>Filtros de exclusão.</li>
  <li>Hosts adicionados manualmente.</li>
  <li>Opções de acessibilidade disponíveis.</li>
</ul>

<h3>Demonstrações em Sala</h3>
<ul>
  <li><b>Hotspot:</b> pode ser utilizado para criar um ambiente controlado de demonstração.</li>
  <li><b>Servidor Lab:</b> utilize o servidor vulnerável exclusivamente no laboratório.</li>
  <li><b>Análise de tráfego:</b> observe como diferentes protocolos geram eventos distintos.</li>
</ul>

<h3>Integração com Outras Ferramentas</h3>
<ul>
  <li><b>Wireshark:</b> pode complementar o NetLab com inspeção detalhada de pacotes.</li>
  <li><b>Diagnóstico:</b> use o relatório para documentar problemas encontrados.</li>
</ul>

<div class="box">
  <b>Objetivo pedagógico:</b> utilize o NetLab para relacionar teoria,
  tráfego real, protocolos, topologia e segurança de redes.
</div>""",
}


def montar_html_secao(corpo: str) -> str:
    """
    Monta o HTML completo de uma seção, envolvendo o corpo com CSS e tags body.
    
    Args:
        corpo: Conteúdo HTML do corpo da seção (sem <style> nem <body>).
    
    Returns:
        HTML completo pronto para ser exibido no QTextBrowser.
    """
    return CSS_MANUAL + "<body>" + corpo + "</body>"
