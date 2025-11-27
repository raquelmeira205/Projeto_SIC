# 🔒 Secure Bluetooth IoT Ad-hoc Network

Este repositório contém a implementação de um projeto de rede ad-hoc segura para dispositivos IoT utilizando Bluetooth Low Energy (BLE).

---

## 🛠️ Estrutura de Pastas

A arquitetura do projeto segue a separação lógica de responsabilidades entre os dispositivos IoT (`node`), a estação central (`sink`), e o código comum a ambos, além das ferramentas de suporte.

| Pasta | Conteúdo Principal | Descrição da Responsabilidade |
| :--- | :--- | :--- |
| **common/** | Módulos Base, Estruturas de Dados e Criptografia | [cite_start]Contém o código compartilhado pelo Sink e pelos Nodes[cite: 146]. [cite_start]Inclui as **definições de pacotes** (NIDs, Hop Count), manipulação de **certificados X.509**, utilitários de **criptografia** (P-521) [cite: 81][cite_start], e lógica para calcular **MACs** por link[cite: 101]. |
| **node/** | Lógica de Roteamento, Heartbeat e UI | [cite_start]Código que roda exclusivamente nos dispositivos IoT (sensores/roteadores)[cite: 145]. [cite_start]Implementa a **topologia em árvore** (escolha do *uplink*) [cite: 31, 34][cite_start], o protocolo de **Heartbeat** para detetar falhas de link [cite: 69][cite_start], o cliente **DTLS** e a **Interface de Utilizador (UI)**[cite: 117]. |
| **sink/** | Serviços de Aplicação e Heartbeat | [cite_start]Código que roda exclusivamente na estação central Sink[cite: 144]. [cite_start]Implementa o serviço de **Heartbeat Broadcast** [cite: 64][cite_start], o serviço de aplicação **Inbox** [cite: 104][cite_start], e o lado servidor do **DTLS**[cite: 113]. |
| **support/** | Ferramentas de Certificação e Provisionamento | [cite_start]Contém o código que não é explorado durante a operação da rede[cite: 147]. [cite_start]Inclui a **Certification Authority (CA)** para emissão de certificados X.509 [cite: 86] [cite_start]e scripts de provisionamento de dispositivos (geração de NIDs)[cite: 54]. |
| **README.md** | Relatório Sucinto e Instruções | [cite_start]Documentação principal que deve incluir o **design, implementação, identificação de autores** e a contribuição percentual de cada um[cite: 148, 149]. |

---
