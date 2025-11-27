# Projeto_SIC
#  secure-bluetooth-iot-adhoc-network

[cite_start]Este repositório contém o código-fonte para o **Projeto SIC: Rede Ad-hoc Segura Baseada em Bluetooth para Dispositivos IoT**[cite: 1, 2].

[cite_start]O objetivo deste projeto é implementar uma rede IPv4 privada de dispositivos IoT que interagem exclusivamente com um host **Sink** através de comunicação multi-hop, utilizando **Bluetooth Low Energy (BLE)** como camada de enlace[cite: 10, 15, 28]. [cite_start]O design da rede é uma topologia em árvore, auto-organizada (ad-hoc), com foco em segurança de ponta a ponta (End-to-End) via **DTLS** e segurança de enlace (Per-Link) via certificados X.509[cite: 31, 106].

---

## 👥 Autores e Contribuição

| Nome do Aluno | Número | Contribuição (%) | Funcionalidades Implementadas |
| :--- | :--- | :--- | :--- |
| [Nome 1] | [Número] | [X]% | [Ex: Implementação inicial da CA, Módulo de Roteamento] |
| [Nome 2] | [Número] | [X]% | [Ex: Protocolo de Heartbeat, Módulo de Comunicação Bluetooth] |
| [Nome 3] | [Número] | [X]% | [Ex: Serviço Inbox, Camada DTLS] |
| [Nome 4] | [Número] | [X]% | [Ex: UI/Network Controls, Testes de Integração] |

### ⚠️ Funcionalidades Pendentes/Parcialmente Implementadas

* [cite_start][Listar funcionalidades não implementadas ou apenas parcialmente implementadas, como, por exemplo: Múltiplos Sinks (Bonus), Interface de utilizador completa, etc.] [cite: 149]

---

## 📁 Estrutura do Repositório

[cite_start]A estrutura de pastas foi desenhada para promover a modularidade e espelhar as responsabilidades lógicas do sistema (Comum, Sink, Node e Suporte), conforme a divisão sugerida no plano de implementação[cite: 144, 145, 146, 147].

### 📦 `common/` (Código Comum)

Esta pasta contém todo o código, bibliotecas e definições de dados que são partilhadas e necessárias tanto para o `sink` quanto para os `node`s (dispositivos IoT).

* [cite_start]**Definições de Rede:** Estruturas de pacotes (headers) para endereçamento com NIDs, campos de hop count e identificação de serviços/clientes[cite: 55, 132].
* [cite_start]**Módulo de Segurança:** Funções e classes para a utilização da **curva elíptica P-521** [cite: 81][cite_start], manipulação de **certificados X.509** [cite: 80][cite_start], e utilitários para cálculo e verificação de **MACs** para garantir integridade e frescor das mensagens (anti-replay)[cite: 101].
* [cite_start]**Comunicação Base:** Utilitários e *wrappers* de baixo nível para abstrair as operações básicas de conexão e transmissão do BLE, compartilhadas por Sink e Nodes[cite: 130, 137].

### 💡 `node/` (Dispositivos IoT)

Esta pasta abriga o código exclusivo que roda em todos os dispositivos IoT (sensores/roteadores).

* [cite_start]**Lógica de Rede (Roteador):** Implementa a regra de topologia em árvore (escolha do *uplink* com menor *hop count* de forma lazy)[cite: 33, 34]. [cite_start]Contém a lógica de manutenção das **Tabelas de Encaminhamento** (Forwarding Tables) [cite: 56, 121] [cite_start]e o mecanismo de **Multi-Hop/Encaminhamento** (Adição/Remoção de MACs por link)[cite: 28, 57, 111].
* [cite_start]**Protocolo de Heartbeat:** Lógica para receber o broadcast do Sink e para o mecanismo de *timeout* (perda de 3 heartbeats em sequência) que dispara a desconexão e a procura por um novo *uplink*[cite: 69, 134].
* [cite_start]**Network Controls:** Implementação dos comandos de debug (Procurar vizinhos, Conectar a vizinho, UI)[cite: 74, 117, 124].
* [cite_start]**DTLS/Serviços:** O código que lida com a proteção **DTLS** para comunicação *End-to-End* segura com o Sink e a lógica de cliente para o serviço **Inbox**[cite: 106, 113, 135, 136].

### 🗄️ `sink/` (Estação Central)

Esta pasta contém o código exclusivo que roda no Sink (Gateway Aplicacional).

* [cite_start]**Serviço Heartbeat:** Implementação do serviço de broadcast (*multi-unicast*) periódico (a cada 5s) dos heartbeats, incluindo a assinatura da mensagem e o contador sucessivo[cite: 64, 65]. [cite_start]Contém também o **Network Control** para simular falha de link (parar o envio de heartbeat a um nó específico)[cite: 76].
* [cite_start]**Serviço Inbox:** A lógica do servidor para o serviço **Inbox**, responsável por receber e registar mensagens arbitrárias enviadas pelos dispositivos IoT[cite: 104, 125].
* [cite_start]**DTLS/Serviços:** O código que lida com a terminação da conexão **DTLS** vinda dos dispositivos IoT e a lógica de servidor para gerir o canal seguro[cite: 113].
* [cite_start]**Roteamento (Downlink):** A lógica para utilizar as tabelas de encaminhamento para enviar mensagens de volta a um dispositivo IoT específico (Downlink)[cite: 60].

### 🛠️ `support/` (Ferramentas de Suporte)

Esta pasta contém ferramentas e scripts que não são executados durante a operação normal da rede, mas que são essenciais para o *setup* e manutenção.

* [cite_start]**Certification Authority (CA):** Scripts e código para atuar como a CA central do sistema, responsável por gerar e assinar os **certificados X.509** para todos os dispositivos IoT e para o Sink[cite: 84, 86, 147].
* [cite_start]**Provisionamento de Dispositivos:** Scripts para gerar os **NIDs de 128 bits** e associá-los aos certificados durante a fase de provisionamento[cite: 54].
* [cite_start]**Testes/Simulação:** Scripts para inicializar e testar a comunicação entre os dispositivos, incluindo a simulação de perda de *uplink* e reentrada na rede[cite: 50, 77].

---

## 🚀 Implementação e Execução

[cite_start]O projeto é recomendado para ser implementado em **hosts Linux** utilizando a biblioteca **simpleBLE** para manipulação do Bluetooth BLE[cite: 137].

Para correr o sistema:

1.  **Setup da CA:** Executar o script de provisionamento em `support/` para gerar certificados e NIDs.
2.  **Iniciar o Sink:** Executar o código em `sink/` (que deve carregar o seu certificado de Sink).
3.  **Iniciar os Nodes:** Executar o código em `node/` (que deve carregar os seus certificados de IoT) e iniciar a procura de *uplinks*.

---

## 📝 Documentação Adicional

* **`docs/`**: Documentação técnica aprofundada, diagramas de sequência de protocolo (e.g., handshake DTLS, troca de heartbeat), e decisões de design justificadas.
* **`LICENSE`**: A licença de código-fonte escolhida.
* **`.gitignore`**: Ficheiro para ignorar *build artifacts*, segredos e binários.
