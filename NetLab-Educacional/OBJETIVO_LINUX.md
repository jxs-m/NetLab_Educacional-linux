# 🎯 Objetivo: Suporte Nativo a Linux no NetLab Educacional

Este documento detalha o objetivo atual de desenvolvimento do projeto **NetLab Educacional**: tornar a aplicação 100% funcional e nativa em ambientes **Linux** (mantendo total retrocompatibilidade com Windows).

---

## 📌 Contexto

O **NetLab Educacional** é uma ferramenta de ensino de redes e cibersegurança baseada em Python, PyQt6 e Scapy. O projeto foi concebido originalmente em ambiente Windows como Trabalho de Conclusão de Curso (TCC) e disponibilizado como software de código aberto.

Embora o núcleo da aplicação utilize bibliotecas multiplataforma, diversas camadas de baixo nível (subprocessos, diagnóstico de sistema, captura de rede e permissões) possuem dependências exclusivas do Windows.

---

## 🎯 Meta Principal

> **Permitir que o NetLab Educacional seja executado nativamente em distribuições Linux (Debian, Ubuntu, Kali, Fedora, Arch, etc.) sem perda de funcionalidades, com detecção automática de sistema operacional e inicialização simplificada.**

---

## 🔍 Diagnóstico dos Bloqueios Atuais no Linux

### Bloqueios Críticos (impedem a aplicação de abrir ou listar interfaces)

| Componente | Arquivo(s) | Comportamento Windows | Problema no Linux | Solução |
|---|---|---|---|---|
| **`creationflags` em subprocess** | 37 ocorrências em 11 arquivos | `creationflags=0x08000000` evita janela de console | `ValueError: creationflags is only supported on Windows` | Centralizar helper `subprocess_kwargs()` em `utils/compat.py` |
| **`import ctypes` → `windll`** | `janela_principal.py` L825, L3165 | `ctypes.windll.shell32.IsUserAnAdmin()` | `AttributeError: module 'ctypes' has no attribute 'windll'` | Usar `os.geteuid() == 0` no Linux (via `utils/compat.py:eh_admin()`) |
| **`import winreg`** | `janela_principal.py` L832 | Lê versão do Npcap do registro do Windows | `ModuleNotFoundError: No module named 'winreg'` | Guard com `os.name == 'nt'`; no Linux, checar libpcap |
| **`scapy.arch.windows`** | `janela_principal.py` L1380, L2585, L3175 | `get_windows_if_list()` para listar interfaces | `ImportError` no Linux (módulo exclusivo de Windows) | Usar `scapy.all.get_if_list()`, `conf.ifaces` e `psutil.net_if_addrs()` |
| **`conf.use_pcap = True`** | `diagnostico.py` L12 | Força uso de pcap via Npcap | No Linux pode causar falha se libpcap não estiver instalada | Condicionar a `os.name == 'nt'` |

### Bloqueios Funcionais (a aplicação abre, mas funcionalidades falham)

| Componente | Arquivo(s) | Comportamento Windows | Problema no Linux | Solução |
|---|---|---|---|---|
| **Comando `ping`** | `janela_principal.py` L889; `diagnostico_conectividade.py` L72 | `ping -n 3 -w 800` | Flags inválidas no Linux (`-n` vs `-c`) | Usar `ping -c 3 -W 1` no Linux |
| **Comando `tracert`** | `diagnostico_conectividade.py` L188 | `tracert -h N -w T alvo` | Comando inexistente no Linux | Usar `traceroute -m N -w T alvo` |
| **Comando `ipconfig`** | `diagnostico_dns.py` L60; `rede.py` L171, L236; `janela_principal.py` L2875 | `ipconfig /all`, `ipconfig /flushdns` | Comando inexistente no Linux | Usar `ip addr`, `resolvectl flush-caches` ou `systemd-resolve --flush-caches` |
| **Comando `netsh wlan`** | `janela_principal.py` L1016 | `netsh wlan show interfaces` (sinal Wi-Fi) | Comando inexistente no Linux | Usar `nmcli -t dev wifi`, `iwconfig` ou `/proc/net/wireless` |
| **Comando `netsh advfirewall`** | `painel_servidor.py` L3288-3344 | Adiciona/remove regras no Windows Firewall | Comando inexistente no Linux | Suporte a `ufw` / `iptables` se root, ou bypass com orientação em tela |
| **Comando `route print -4`** | `janela_principal.py` L952 | Lê tabela de rotas IPv4 do Windows | Formato diferente no Linux | Usar `ip -4 route show` (já implementado em `gerenciador_subredes.py`) |
| **Tabela ARP (`arp -a`)** | `janela_principal.py` L3716 | Parsing de `arp -a` formato Windows | Formato diferente no Linux | Usar `ip neigh` (já parcialmente implementado na mesma função) |
| **Detecção de CIDR/Gateway via PowerShell** | `rede.py` L128-155, L204-231; `janela_principal.py` L2844-2868, L2962-2983 | `Get-NetIPAddress`, `Get-WmiObject`, `Get-NetRoute` | PowerShell inexistente no Linux | Priorizar caminhos `psutil`, `scapy.conf.route` e `ip route` |
| **Perfil de rede Windows** | `painel_servidor.py` L3160-3181 | `Get-NetConnectionProfile` (Pública/Privada) | Conceito inexistente no Linux | Retornar "Linux (Local/LAN)" ou detectar via NetworkManager |
| **Versão do Npcap** | `janela_principal.py` L829-851 | Lê do registro do Windows + DLL `wpcap.dll` | Npcap não existe no Linux | Verificar `libpcap` (`ldconfig -p \| grep libpcap` ou checagem de shared lib) |
| **Exibição do Diagnóstico de SO** | `painel_diagnosticos.py` L438-449; `janela_principal.py` L528-534, L583-599 | Renderiza fixo `<h2>Sistema Windows</h2>` (Defender, Winsock) | Não reflete a segurança do Linux | Renderizar seção `Sistema Linux` (UFW, iptables, AppArmor/SELinux, Raw Sockets) |

### Módulos Inteiros com Especialização por SO

| Módulo | Função | Comandos Windows Usados | Equivalente Linux |
|---|---|---|---|
| `utils/diagnostico_windows.py` | Firewall, Defender, Winsock, NDIS, VPN | PowerShell (`Get-NetFirewallProfile`, `Get-MpComputerStatus`, `netsh winsock`, `Get-NetAdapter`) | `ufw status`, `ss`/`ip link`, verificar AppArmor/SELinux |
| `utils/diagnostico_linux.py` | **NOVO** — Diagnóstico de SO Linux | N/A | `ufw status`, `iptables -L`, checagem de Raw Socket, AppArmor, VPN via `ip link` |
| `utils/diagnostico_camada_fisica.py` | Velocidade, duplex, erros, MTU | PowerShell (`Get-NetAdapter`, `Get-NetAdapterStatistics`) | `/sys/class/net/*/speed`, `/sys/class/net/*/operstate`, `ethtool`, `ip -j link show` |
| `utils/diagnostico_ip_config.py` | Coleta completa de config IP | PowerShell (`Get-NetIPConfiguration`) | `ip -j addr show`, `psutil.net_if_addrs()`, `resolvectl status` |
| `utils/diagnostico_subrede.py` | Detecção de IPs duplicados | PowerShell (`Get-NetNeighbor`) | `ip neigh show`, `/proc/net/arp` |
| `utils/diagnostico_descoberta.py` | Dispositivos conectados | PowerShell (`Get-NetNeighbor -State Reachable`) | `ip neigh show`, varredura ARP via Scapy |
| `utils/diagnostico_dns.py` | Servidores DNS configurados, flush cache | `ipconfig /all`, `ipconfig /flushdns` | `/etc/resolv.conf`, `resolvectl`, `systemd-resolve --flush-caches` |
| `utils/diagnostico_conectividade.py` | Ping e traceroute | `ping -n`, `tracert` | `ping -c`, `traceroute` |
| `utils/diagnostico_avancado.py` | Orquestrador — despacha por SO | Chama `obter_interfaces_windows()`, `obter_configuracao_ip_windows()`, `diagnostico_windows_completo()` | Chamar despachantes cross-platform / Linux conforme `os.name` |

### Permissões de Captura de Pacotes no Linux

No Linux, captura com sockets raw (`AsyncSniffer`) e envio de pacotes ARP necessitam de privilégios elevados. Duas abordagens são suportadas:
1. **Execução direta com superusuário:** `sudo python3 main.py` (ou via launcher `run.sh`).
2. **Execução sem sudo via Linux Capabilities:**
   ```bash
   sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
   ```

---

## 🗺️ Roadmap de Implementação

### 🔹 Fase 1: Desbloqueio e Inicialização Básica
**Objetivo:** A janela principal abre sem erros e lista as interfaces de rede no Linux.

- [ ] Criar módulo central `utils/compat.py` com:
  - `eh_windows() -> bool` e `eh_linux() -> bool`
  - `subprocess_kwargs() -> dict` (retorna `{"creationflags": 0x08000000}` no Windows, `{}` no Linux)
  - `eh_admin() -> bool` (`ctypes.windll...` no Windows, `os.geteuid() == 0` no Linux)
  - `obter_versao_driver_captura() -> str` (Npcap no Windows, libpcap no Linux)
- [ ] Aplicar `subprocess_kwargs()` em todas as 37 ocorrências no projeto.
- [ ] Tornar `_verificar_admin()` em `interface/janela_principal.py` agnóstica a SO usando `compat.eh_admin()`.
- [ ] Proteger `import winreg` e `_versao_npcap()` com guard `os.name == 'nt'`; no Linux, consultar `libpcap`.
- [ ] Atualizar `obter_interfaces_disponiveis()` (L1380) e `_popular_interfaces()` (L2585) para usar `psutil.net_if_addrs()` / `scapy.all.get_if_list()` no Linux.
- [ ] Proteger `_validar_pre_captura()` (L3175) contra import exclusivo de `scapy.arch.windows` no Linux.
- [ ] Condicionar `conf.use_pcap = True` em `diagnostico.py` a `os.name == 'nt'`.
- [ ] **Teste de Validação:** A interface gráfica abre e lista interfaces de rede no Linux sem exceções no console.

### 🔹 Fase 2: Captura de Pacotes e Rede Cross-Platform
**Objetivo:** Captura de tráfego em tempo real, topologia e comandos de rede funcionais no Linux.

- [ ] Atualizar `utils/rede.py` — funções `detectar_cidr_robusto()` e `detectar_gateway_robusto()` — para priorizar caminhos cross-platform (`psutil`, `scapy.conf.route`, `ip route`) no Linux.
- [ ] Corrigir `ping` em `janela_principal.py` (`_testar_ping_gateway`) e `diagnostico_conectividade.py`: usar `-c` no Linux, `-n` no Windows.
- [ ] Corrigir `tracert` → `traceroute` em `diagnostico_conectividade.py`.
- [ ] Harmonizar parsing de tabela ARP em `_obter_tabela_arp_sistema()` (`ip neigh` no Linux, `arp -a` no Windows).
- [ ] Adaptar leitura de sinal Wi-Fi em `_sinal_wifi()`: suportar `nmcli`, `iwconfig` ou `/proc/net/wireless` no Linux.
- [ ] Validar extração de rotas em `utils/gerenciador_subredes.py` via `ip -4 route show`.
- [ ] **Teste de Validação:** Captura de pacotes inicia, nós são adicionados na topologia, gráfico de tráfego atualiza em tempo real.

### 🔹 Fase 3: Módulos de Diagnóstico & Servidor
**Objetivo:** Painel de diagnósticos completo e servidor de laboratório funcionais no Linux.

- [ ] Criar `utils/diagnostico_linux.py` com verificações: `ufw status`, `iptables`, permissões de raw socket, interface ativa, VPN via `ip link`.
- [ ] Adaptar `utils/diagnostico_avancado.py` (orquestrador): despachar para coletores Windows ou Linux conforme `os.name`.
- [ ] Adaptar `utils/diagnostico_camada_fisica.py`: ler dados de `/sys/class/net/*/speed`, `operstate` e `ethtool` no Linux.
- [ ] Adaptar `utils/diagnostico_ip_config.py`: usar `ip -j addr show` e `psutil` no Linux.
- [ ] Adaptar `utils/diagnostico_subrede.py` (`detectar_ips_duplicados()`): usar `ip neigh show` no Linux.
- [ ] Adaptar `utils/diagnostico_descoberta.py` (`obter_dispositivos_conectados()`): usar `ip neigh` no Linux.
- [ ] Adaptar `utils/diagnostico_dns.py`: ler DNS de `/etc/resolv.conf` e usar `resolvectl flush-caches` no Linux.
- [ ] Adaptar `interface/painel_diagnosticos.py` (L438-449) e `interface/janela_principal.py` (L507-600) para exibir os diagnósticos específicos do Linux.
- [ ] Ajustar `painel_servidor.py`: ignorar `Get-NetConnectionProfile`; usar `ufw` ou orientar liberação manual no Linux.
- [ ] **Teste de Validação:** O painel de diagnósticos executa 100% dos testes e gera o relatório completo no Linux.

### 🔹 Fase 4: Experiência Linux, Launcher & Polimento
**Objetivo:** Experiência nativa, scripts de automação e documentação completa.

- [ ] Adaptar textos em `interface/conteudo_manual.py` para serem cross-platform (mencionar libpcap, sudo e capabilities).
- [ ] Adaptar mensagens em `diagnostico.py` para Linux (libpcap em vez de Npcap, root em vez de Administrador).
- [ ] Suporte a ícone `.png` em `main.py` para compatibilidade com temas e docks do Linux.
- [ ] Criar script de execução rápida (`run.sh`) que verifica dependências do sistema (`libpcap`, `python3`, `pip`) e privilégios (`sudo` / capabilities).
- [ ] Criar arquivo `.desktop` para integração com menus de aplicativos do Linux.
- [ ] Atualizar `README.md` com instruções completas de instalação para Debian, Ubuntu, Kali, Arch e Fedora.
- [ ] Testar execução completa end-to-end em ambiente Linux (ex: Kali Linux / Ubuntu).

---

## 📋 Critérios de Aceitação (Definition of Done)

1. A aplicação inicia sem erros via terminal (`sudo python3 main.py` ou `./run.sh`).
2. As interfaces de rede ativas (Wi-Fi, Ethernet) são listadas e selecionáveis na barra superior.
3. A captura de tráfego em tempo real funciona e popula a Topologia, o Gráfico de Tráfego e a Lista de Eventos.
4. O painel de diagnósticos executa e exibe relatório completo sem erros no Linux.
5. O servidor vulnerável de laboratório inicia e aceita requisições normalmente.
6. O código continua 100% funcional no Windows (sem quebras de retrocompatibilidade).

---

## 📊 Inventário Completo de Arquivos Afetados

| Arquivo | Tipo de Alteração | Descrição Resumida | Fase |
|---|---|---|:---:|
| `utils/compat.py` | **NOVO** | Helper centralizado (`subprocess_kwargs`, `eh_admin`, `eh_linux`, etc.) | **1** |
| `diagnostico.py` | Modificar | `conf.use_pcap` condicional e mensagens adaptadas | **1, 4** |
| `interface/janela_principal.py` | Modificar | Admin (L825, 3165), scapy.arch (L1380, 2585, 3175), ping (L889), Wi-Fi (L1016), interfaces (L2730), diag (L507-600), subprocess kwargs (10 locais) | **1, 2, 3** |
| `utils/rede.py` | Modificar | Detecção de CIDR/Gateway cross-platform e remoção de `creationflags` fixo (6 locais) | **2** |
| `utils/gerenciador_subredes.py` | Modificar | Validação de rotas Linux (`ip -4 route`) e subprocess kwargs | **2** |
| `utils/diagnostico_conectividade.py` | Modificar | Flags do ping (`-c` vs `-n`), comando `traceroute` e subprocess kwargs | **2** |
| `utils/diagnostico_windows.py` | Modificar | Guard para execução apenas quando `os.name == 'nt'` | **3** |
| `utils/diagnostico_linux.py` | **NOVO** | Diagnóstico de SO equivalente para Linux (UFW, raw sockets, VPN) | **3** |
| `utils/diagnostico_avancado.py` | Modificar | Orquestrador para despachar coletores por SO | **3** |
| `utils/diagnostico_camada_fisica.py` | Modificar | Adicionar leitura via `/sys/class/net/` e `ethtool` no Linux | **3** |
| `utils/diagnostico_ip_config.py` | Modificar | Adicionar coleta via `ip -j addr` e `psutil` no Linux | **3** |
| `utils/diagnostico_subrede.py` | Modificar | Detecção de IPs duplicados via `ip neigh` no Linux | **3** |
| `utils/diagnostico_descoberta.py` | Modificar | Descoberta via `ip neigh` no Linux | **3** |
| `utils/diagnostico_dns.py` | Modificar | Leitura de `/etc/resolv.conf` e flush via `resolvectl` | **3** |
| `interface/painel_diagnosticos.py` | Modificar | Renderização do relatório HTML adaptada para Linux (L438-449) | **3** |
| `painel_servidor.py` | Modificar | Regras de firewall (`ufw`/`iptables`) e perfil de rede no Linux | **3** |
| `interface/conteudo_manual.py` | Modificar | Textos didáticos multi-SO (mencionar libpcap, sudo e capabilities) | **4** |
| `main.py` | Modificar | Suporte a ícone `.png` e scaling no Linux | **4** |
| `run.sh` | **NOVO** | Launcher bash com checagem de dependências e permissões | **4** |
| `netlab.desktop` | **NOVO** | Atalho de aplicativo para menus do Linux | **4** |
| `README.md` | Modificar | Instruções de instalação e execução para distribuições Linux | **4** |
