# 🔒 Secure Bluetooth IoT Ad-hoc Network

Este repositório contém a implementação de um projeto de rede ad-hoc segura para dispositivos IoT utilizando Bluetooth Low Energy (BLE).

---

## 🛠️ Estrutura de Pastas

A arquitetura do projeto segue a separação lógica de responsabilidades entre os dispositivos IoT (`node`), a estação central (`sink`), e o código comum a ambos, além das ferramentas de suporte.

| Pasta | Conteúdo Principal | Descrição da Responsabilidade |
| :--- | :--- | :--- |
| **common/** | Módulos Base, Estruturas de Dados e Criptografia | Contém o código compartilhado pelo Sink e pelos Nodes. Inclui as **definições de pacotes** (NIDs, Hop Count), manipulação de **certificados X.509**, utilitários de **criptografia** (P-521, HMAC-SHA256), e lógica de **Security Handshake**. |
| **node/** | Lógica de Roteamento, Heartbeat e UI | Código que roda exclusivamente nos dispositivos IoT (sensores/roteadores). Implementa a **topologia em árvore** (escolha do *uplink*), o protocolo de **Heartbeat** para detetar falhas de link, o cliente **DTLS** e a **Interface de Utilizador (UI)**. |
| **sink/** | Serviços de Aplicação e Heartbeat | Código que roda exclusivamente na estação central Sink. Implementa o serviço de **Heartbeat Broadcast**, o serviço de aplicação **Inbox**, e o lado servidor do **DTLS**. |
| **support/** | Ferramentas de Certificação e Provisionamento | Contém o código que não é explorado durante a operação da rede. Inclui a **Certification Authority (CA)** para emissão de certificados X.509 e scripts de provisionamento de dispositivos (geração de NIDs). |
| **README.md** | Relatório Sucinto e Instruções | Documentação principal do projeto. |

---

## 🛡️ Segurança (Implementação e Auditoria)

### Link Layer Security (Integridade e Replay Protection)
Implementámos segurança "Hop-by-Hop" para garantir que, em cada salto da rede ad-hoc, as mensagens são autênticas e frescas.

#### 1. Mecanismo de Integridade (MAC)
- Utilizamos **HMAC-SHA256** para gerar um Message Authentication Code (MAC) de 32 bytes para cada pacote.
- O MAC cobre todo o conteúdo do pacote (Common Header + Payload), garantindo que nem o cabeçalho (Src/Dest) nem os dados foram alterados.
- O campo MAC foi adicionado ao fim do `PacketHeader`.

#### 2. Proteção contra Replay
- Adicionámos um **Sequence Number** (4 bytes) ao `PacketHeader`.
- Cada Router mantém um contador de saída (`my_counters`) e um registo do último número de sequência válido recebido de cada vizinho (`replay_counters`).
- Pacotes com `seq <= last_seen` são descartados imediatamente.

#### 3. Estrutura do Pacote Seguro
O novo cabeçalho (`PacketHeader` v2) tem o seguinte formato:
- `Source NID` (16 bytes)
- `Dest NID` (16 bytes)
- `Msg Type` (1 byte)
- `Payload Len` (2 bytes)
- `Sequence Number` (4 bytes) **[Novo]**
- `MAC` (32 bytes) **[Novo]**

### Auditoria e Limitações Atuais
- **Gestão de Chaves**: A integração completa entre o módulo de Handshake (`SecurityHandshake`) e o Router ainda requer refinamento. O Router atualmente suporta o armazenamento de chaves por link, mas o trigger do handshake deve ser feito aquando da conexão BLE. Atualmente o Router utiliza chaves pré-definidas/test keys na ausência de handshake completo.
- **Loopback**: Pacotes locais (loopback) são considerados confiáveis e bypassam verificações criptográficas.
