---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![WELA](assets/screenshots/WELA-Logo.png){ .hb-logo }

<p class="hb-tagline">
O <strong>WELA</strong> (Windows Event Log Analyzer, ゑ羅), criado pela
<a href="https://github.com/Yamato-Security">Yamato Security</a>, é uma ferramenta para
<strong>auditar as configurações de log de eventos do Windows</strong>. Os logs de eventos do Windows são uma fonte vital de
informações para DFIR — o WELA ajuda você a garantir que está de fato registrando os eventos que importam.
</p>

<div class="hb-cta" markdown>
[Começar :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[Referência de Comandos :material-console:](commands/index.md){ .md-button }
[Ver no GitHub :fontawesome-brands-github:](https://github.com/Yamato-Security/WELA){ .md-button }
</div>

<p class="hb-badges">
<a href="https://github.com/Yamato-Security/WELA/releases"><img src="https://img.shields.io/github/v/release/Yamato-Security/WELA?color=blue&label=Stable%20Version&style=flat"/></a>
<a href="https://github.com/Yamato-Security/WELA/releases"><img src="https://img.shields.io/github/downloads/Yamato-Security/WELA/total?style=flat&label=GitHub%F0%9F%A6%85Downloads&color=blue"/></a>
<a href="https://github.com/Yamato-Security/WELA/stargazers"><img src="https://img.shields.io/github/stars/Yamato-Security/WELA?style=flat&label=GitHub%F0%9F%A6%85Stars"/></a>
<a href="https://github.com/Yamato-Security/WELA/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=flat"/></a>
<a href="https://conference.auscert.org.au/speaker/fukusuke-takahashi/"><img src="https://img.shields.io/badge/AUSCERT-2025-blue"></a>
<a href="https://www.infosec-city.com/sin-25"><img src="https://img.shields.io/badge/SINCON-2025-blue"></a>
<a href="https://codeblue.jp/program/time-table/day2-t3-02/"><img src="https://img.shields.io/badge/CODE%20BLUE-2025-blue"></a>
<a href="https://twitter.com/SecurityYamato"><img src="https://img.shields.io/twitter/follow/SecurityYamato?style=social"/></a>
</p>

</div>

---

## Por que WELA?

<div class="grid cards" markdown>

-   :material-clipboard-check:{ .lg .middle } __Auditar configurações de política de log__

    ---

    Audite as **configurações de política de auditoria** do log de eventos do Windows para confirmar que os eventos certos estão sendo registrados.

-   :material-book-check:{ .lg .middle } __Baseado em diretrizes__

    ---

    Verifica em relação às **principais diretrizes de configuração de auditoria de log de eventos do Windows**.

-   :material-shield-search:{ .lg .middle } __Detectabilidade do Sigma__

    ---

    Avalia suas configurações em relação à **detectabilidade real de regras Sigma** — seus logs realmente vão capturar ataques?

-   :material-file-cog:{ .lg .middle } __Auditoria de tamanho de arquivo__

    ---

    Audita os **tamanhos de arquivo** do log de eventos do Windows e sugere tamanhos recomendados.

-   :material-cog-play:{ .lg .middle } __Configuração automática__

    ---

    Aplique a política de auditoria e os tamanhos de arquivo de log **recomendados** com o comando `configure`.

-   :material-chart-box:{ .lg .middle } __Saída flexível__

    ---

    Veja os resultados no terminal, em uma GUI, em uma tabela ou como um mapa de calor do **MITRE ATT&CK Navigator**.

</div>

## Links rápidos

<div class="grid cards" markdown>

-   __:material-book-open-variant: Novo por aqui?__

    Comece pela [Visão geral](overview/index.md) e, em seguida, vá para
    [Primeiros passos](getting-started/index.md) para instalar e executar o WELA.

-   __:material-console-line: Trabalhando com a CLI?__

    Navegue pela [Lista de Comandos](commands/index.md) e pela referência de
    [Uso dos Comandos](commands/usage.md) (`audit-settings`, `audit-filesize`, `configure`, `update-rules`).

-   __:material-puzzle: Indo mais além?__

    Explore os [Projetos Complementares](resources/companion-projects.md), o
    [Changelog](resources/changelog.md) e como
    [contribuir](resources/contributing.md).

</div>
