"""
utils/config_manager.py
Gerencia a persistência das configurações do NetLab em JSON.

Todas as configurações são salvas em: dados/config_netlab.json
"""

from __future__ import annotations

import json
import os
import threading
import ipaddress
from typing import Any, List, Optional

# ── Caminho do arquivo de configuração ───────────────────────────────────────

def _caminho_config() -> str:
    """Retorna o caminho absoluto do arquivo de configurações."""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pasta = os.path.join(base, "dados")
    os.makedirs(pasta, exist_ok=True)
    return os.path.join(pasta, "config_netlab.json")


# ── Valores padrão ───────────────────────────────────────────────────────────

CONFIG_PADRAO: dict = {
    # Geral
    "limite_hosts":             100,
    "apenas_subrede_local":     False,
    "timer_redescoberta_s":     30,
    "timeout_arp_s":            1.8,
    "arp_batch":                32,
    "arp_tentativas":           2,
    "arp_inter":                0.02,
    "arp_pausa":                1.0,

    # Filtros de rede
    "subredes_priorizadas":     [],   # lista de CIDRs (str)
    "subredes_excluidas":       [],   # lista de CIDRs (str)
    "filtro_oui":               [],   # lista de prefixos MAC (str)

    # Gerenciamento de hosts
    "hosts_excluidos":          [],   # lista de IPs (str)
    "hosts_manuais":            [],   # lista de dicts {ip, hostname, mac, nota}

    # Interface
    "fonte_tamanho":            10,   # tamanho base da fonte em pontos (8–20)
    "tema_escuro":              True, # reservado — preferência salva; tema claro em versão futura
}


# ── Classe principal ─────────────────────────────────────────────────────────

class ConfigManager:
    """
    Gerenciador de configurações com persistência JSON e thread-safety.

    Exemplo de uso:
        cfg = ConfigManager()
        limite = cfg.obter("limite_hosts", 100)
        cfg.definir("limite_hosts", 200)
        cfg.salvar()
    """

    _instancia: Optional["ConfigManager"] = None
    _lock_instancia = threading.Lock()

    def __init__(self):
        self._lock    = threading.Lock()
        self._config  = dict(CONFIG_PADRAO)
        self._caminho = _caminho_config()
        self.carregar()

    # ── Singleton opcional ────────────────────────────────────────────────────

    @classmethod
    def instancia(cls) -> "ConfigManager":
        """Retorna a instância singleton do ConfigManager."""
        with cls._lock_instancia:
            if cls._instancia is None:
                cls._instancia = cls()
        return cls._instancia

    # ── Persistência ─────────────────────────────────────────────────────────

    def carregar(self) -> bool:
        """Carrega configurações do arquivo JSON. Retorna True se bem-sucedido."""
        try:
            if not os.path.exists(self._caminho):
                return False
            with open(self._caminho, "r", encoding="utf-8") as f:
                dados = json.load(f)
            with self._lock:
                # Mescla com padrões para garantir que novas chaves existam
                config_merged = dict(CONFIG_PADRAO)
                config_merged.update(dados)
                self._config = config_merged
            return True
        except Exception as e:
            print(f"[ConfigManager] Erro ao carregar configurações: {e}")
            return False

    def salvar(self) -> bool:
        """Persiste as configurações no arquivo JSON. Retorna True se bem-sucedido."""
        try:
            with self._lock:
                dados = dict(self._config)
            with open(self._caminho, "w", encoding="utf-8") as f:
                json.dump(dados, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"[ConfigManager] Erro ao salvar configurações: {e}")
            return False

    def exportar(self, caminho_destino: str) -> bool:
        """Exporta as configurações para um arquivo externo."""
        try:
            with self._lock:
                dados = dict(self._config)
            with open(caminho_destino, "w", encoding="utf-8") as f:
                json.dump(dados, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"[ConfigManager] Erro ao exportar: {e}")
            return False

    def importar(self, caminho_origem: str) -> bool:
        """Importa configurações de um arquivo externo, mesclando com os padrões."""
        try:
            with open(caminho_origem, "r", encoding="utf-8") as f:
                dados = json.load(f)
            with self._lock:
                config_merged = dict(CONFIG_PADRAO)
                config_merged.update(dados)
                self._config = config_merged
            self.salvar()
            return True
        except Exception as e:
            print(f"[ConfigManager] Erro ao importar: {e}")
            return False

    def resetar_para_padrao(self):
        """Restaura todas as configurações para os valores padrão."""
        with self._lock:
            self._config = dict(CONFIG_PADRAO)
        self.salvar()

    # ── Acesso genérico ───────────────────────────────────────────────────────

    def obter(self, chave: str, padrao: Any = None) -> Any:
        """Retorna o valor de uma configuração, ou `padrao` se não existir."""
        with self._lock:
            return self._config.get(chave, padrao)

    def definir(self, chave: str, valor: Any):
        """Define o valor de uma configuração (não persiste automaticamente)."""
        with self._lock:
            self._config[chave] = valor

    def obter_tudo(self) -> dict:
        """Retorna uma cópia de todas as configurações."""
        with self._lock:
            return dict(self._config)

    def atualizar(self, novos_valores: dict):
        """Atualiza múltiplos valores de uma só vez."""
        with self._lock:
            self._config.update(novos_valores)

    # ── Helpers de alto nível ─────────────────────────────────────────────────

    @property
    def limite_hosts(self) -> int:
        return int(self.obter("limite_hosts", CONFIG_PADRAO["limite_hosts"]))

    @property
    def apenas_subrede_local(self) -> bool:
        return bool(self.obter("apenas_subrede_local", False))

    @property
    def subredes_priorizadas(self) -> List[str]:
        return list(self.obter("subredes_priorizadas", []))

    @property
    def subredes_excluidas(self) -> List[str]:
        return list(self.obter("subredes_excluidas", []))

    @property
    def filtro_oui(self) -> List[str]:
        return [o.lower().replace("-", ":") for o in self.obter("filtro_oui", [])]

    @property
    def hosts_excluidos(self) -> List[str]:
        return list(self.obter("hosts_excluidos", []))

    @property
    def hosts_manuais(self) -> List[dict]:
        return list(self.obter("hosts_manuais", []))

    @property
    def fonte_tamanho(self) -> int:
        return int(self.obter("fonte_tamanho", CONFIG_PADRAO["fonte_tamanho"]))

    # ── Gerenciamento de listas ───────────────────────────────────────────────

    def adicionar_host_excluido(self, ip: str):
        """Adiciona um IP à lista de exclusão."""
        with self._lock:
            lista = self._config.setdefault("hosts_excluidos", [])
            if ip not in lista:
                lista.append(ip)

    def remover_host_excluido(self, ip: str):
        """Remove um IP da lista de exclusão."""
        with self._lock:
            lista = self._config.get("hosts_excluidos", [])
            if ip in lista:
                lista.remove(ip)

    def adicionar_host_manual(self, ip: str, hostname: str = "", mac: str = "", nota: str = ""):
        """Adiciona um host manual. Substitui se o IP já existir."""
        entrada = {"ip": ip, "hostname": hostname, "mac": mac, "nota": nota}
        with self._lock:
            lista = self._config.setdefault("hosts_manuais", [])
            # Substitui entrada existente com mesmo IP
            for i, h in enumerate(lista):
                if h.get("ip") == ip:
                    lista[i] = entrada
                    return
            lista.append(entrada)

    def remover_host_manual(self, ip: str):
        """Remove um host manual pelo IP."""
        with self._lock:
            lista = self._config.get("hosts_manuais", [])
            self._config["hosts_manuais"] = [h for h in lista if h.get("ip") != ip]

    def adicionar_subrede_priorizada(self, cidr: str) -> bool:
        """Adiciona um CIDR à lista de sub-redes priorizadas. Retorna False se inválido."""
        try:
            cidr_normalizado = str(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            return False
        with self._lock:
            lista = self._config.setdefault("subredes_priorizadas", [])
            if cidr_normalizado not in lista:
                lista.append(cidr_normalizado)
        return True

    def remover_subrede_priorizada(self, cidr: str):
        """Remove um CIDR da lista de sub-redes priorizadas."""
        with self._lock:
            lista = self._config.get("subredes_priorizadas", [])
            if cidr in lista:
                lista.remove(cidr)

    def adicionar_subrede_excluida(self, cidr: str) -> bool:
        """Adiciona um CIDR à lista de sub-redes excluídas. Retorna False se inválido."""
        try:
            cidr_normalizado = str(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            return False
        with self._lock:
            lista = self._config.setdefault("subredes_excluidas", [])
            if cidr_normalizado not in lista:
                lista.append(cidr_normalizado)
        return True

    def remover_subrede_excluida(self, cidr: str):
        """Remove um CIDR da lista de sub-redes excluídas."""
        with self._lock:
            lista = self._config.get("subredes_excluidas", [])
            if cidr in lista:
                lista.remove(cidr)

    # ── Métodos de consulta de filtro ─────────────────────────────────────────

    def ip_esta_excluido(self, ip: str) -> bool:
        """Retorna True se o IP está na lista de exclusão."""
        return ip in self.hosts_excluidos

    def subrede_esta_excluida(self, ip: str) -> bool:
        """Retorna True se o IP pertence a alguma sub-rede excluída."""
        excluidas = self.subredes_excluidas
        if not excluidas:
            return False
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in excluidas:
                try:
                    if ip_obj in ipaddress.ip_network(cidr, strict=False):
                        return True
                except ValueError:
                    continue
        except ValueError:
            pass
        return False

    def ip_passa_filtro_oui(self, mac: str) -> bool:
        """
        Retorna True se o MAC passa pelo filtro OUI configurado.
        Se nenhum filtro OUI estiver definido, retorna sempre True.
        """
        filtros = self.filtro_oui
        if not filtros:
            return True
        if not mac:
            return False
        mac_norm = mac.lower().replace("-", ":").replace(".", ":")
        for prefixo in filtros:
            if mac_norm.startswith(prefixo.lower()):
                return True
        return False

    def ip_pertence_a_subrede_local(self, ip: str, cidr_local: str) -> bool:
        """Retorna True se o IP pertence ao CIDR local."""
        if not cidr_local:
            return True  # Sem CIDR definido, não filtra
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr_local, strict=False)
        except ValueError:
            return True

    def ip_deve_ser_exibido(self, ip: str, mac: str = "", cidr_local: str = "") -> bool:
        """
        Retorna True se o IP deve ser exibido na topologia,
        considerando todos os filtros ativos.
        """
        # Filtro: lista de exclusão de IPs
        if self.ip_esta_excluido(ip):
            return False

        # Filtro: sub-redes excluídas
        if self.subrede_esta_excluida(ip):
            return False

        # Filtro: apenas sub-rede local
        if self.apenas_subrede_local and cidr_local:
            if not self.ip_pertence_a_subrede_local(ip, cidr_local):
                return False

        # Filtro: OUI / fabricante
        if mac and not self.ip_passa_filtro_oui(mac):
            return False

        return True
