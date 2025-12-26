# 🔒 Secure IoT Ad-hoc Network over BLE GATT

Este repositório contém a implementação de uma rede ad-hoc segura para dispositivos IoT utilizando **Bluetooth Low Energy (BLE) GATT** com roteamento multi-hop customizado.

> **⚠️ Nota Importante**: Este projeto **NÃO utiliza BLE Mesh**. Utiliza conexões BLE GATT padrão ponto-a-ponto com roteamento implementado na camada de aplicação.

---

## ⚙️ Setup do Ambiente

### 1. Configuração do Virtual Environment

#### Se já tiverem um ambiente virtual (venv) antigo:
```bash
# Remover venv antigo
sudo rm -rf venv/
```

#### Criar novo ambiente virtual:
```bash
# Atualizar sistema
sudo apt update

# Criar venv com acesso aos pacotes do sistema (necessário para PyGObject)
python3 -m venv --system-site-packages venv

# Ativar venv
source venv/bin/activate

# Instalar dependências
pip install -r requirements.txt
```

### 2. Configuração do Bluetooth

**⚠️ IMPORTANTE**: Sempre que ligarem a VM ou conectarem dongles BLE, devem executar estes passos!

#### Iniciar serviço Bluetooth:
```bash
sudo systemctl start bluetooth
```

#### Para Kali/Ubuntu - Desativar gestor nativo:
```bash
# Matar blueman (gestor de Bluetooth nativo que causa conflitos)
pkill blueman
```

> **⚠️ ATENÇÃO**: Após matar o blueman, **NÃO abram aplicações de Bluetooth** do Linux please xD se não vão ter que o matar de novo!

#### Configurar adaptador BLE:
```bash
bluetoothctl
```

Dentro do `bluetoothctl`, executar:
```
power on
discoverable on
pairable on
advertise on
```

Para verificar a configuração:
```
show
```

Para sair:
```
exit
```

### 3. Entre Execuções

**Sempre que terminarem de correr um programa** e quiserem executar novamente ou outro programa:

```bash
sudo systemctl restart bluetooth
```

Isto evita que fiquem processos ou conexões empancadas do BlueZ.

---

## 📡 Arquitetura da Rede

### Topologia em Árvore
- **Sink**: Estação central (raiz da árvore) que recebe dados de todos os nós
- **Nodes**: Dispositivos IoT que se conectam ao Sink ou a outros Nodes via BLE GATT
- Cada Node mantém **uma conexão BLE** com seu *uplink* (nó pai)
- Nodes podem aceitar **múltiplas conexões** de *downlinks* (nós filhos)

### Tecnologia BLE
- **BLE GATT** (Generic Attribute Profile) padrão
- Conexões ponto-a-ponto entre dispositivos
- Serviço GATT customizado para troca de pacotes
- **Não requer BLE Mesh** - funciona com qualquer adaptador BLE padrão

---

## 🛠️ Estrutura de Pastas

| Pasta | Conteúdo Principal | Descrição |
| :--- | :--- | :--- |
| **common/** | Módulos Compartilhados | Código comum ao Sink e Nodes: estruturas de pacotes, handshake TLS-style, criptografia (ECDSA P-256, HMAC-SHA256), utilitários BLE/GATT |
| **node/** | Lógica do Node IoT | Roteamento multi-hop, seleção de uplink, heartbeat timeout, BLE manager, interface CLI |
| **sink/** | Lógica do Sink | Heartbeat broadcast, gestão de conexões, recepção de dados |
| **support/** | Ferramentas PKI | Certification Authority (CA), geração de certificados X.509, scripts de provisionamento |
| **certs/** | Certificados | Certificados X.509 para Sink e Nodes |

---

## ✅ Funcionalidades Implementadas

### 🔐 Segurança

#### 1. Handshake TLS-Style
- **Autenticação mútua** usando certificados X.509 (ECDSA P-256)
- **Estabelecimento de chave de sessão** via ECDH
- Troca de 4 mensagens:
  1. Node → Sink: ClientHello (certificado + nonce)
  2. Sink → Node: ServerHello (certificado + nonce)
  3. Node → Sink: ClientKeyExchange (ECDH public key)
  4. Sink → Node: ServerKeyExchange (ECDH public key)
- Chave de sessão derivada via ECDH para cada conexão

#### 2. Link Layer Security (Hop-by-Hop)
- **HMAC-SHA256** (32 bytes) para integridade de pacotes
- **Sequence Numbers** (4 bytes) para proteção contra replay attacks
- Cada pacote autenticado com MAC usando a chave de sessão
- Verificação de MAC em cada salto da rede

#### 3. Heartbeat com Assinatura Digital
- Sink envia heartbeats periódicos (5s) assinados com sua chave privada
- Nodes verificam assinatura usando certificado do Sink
- Deteção de perda de uplink após 3 heartbeats perdidos (15s)
- Heartbeats propagados pela árvore (hop count incrementado)

### 📦 Protocolo de Pacotes

#### Estrutura do PacketHeader
```
┌─────────────────────┬─────────┐
│ Source NID          │ 16 bytes│
├─────────────────────┼─────────┤
│ Dest NID            │ 16 bytes│
├─────────────────────┼─────────┤
│ Message Type        │  1 byte │
├─────────────────────┼─────────┤
│ Payload Length      │  2 bytes│
├─────────────────────┼─────────┤
│ Sequence Number     │  4 bytes│
├─────────────────────┼─────────┤
│ MAC (HMAC-SHA256)   │ 32 bytes│
├─────────────────────┼─────────┤
│ Payload             │ Variable│
└─────────────────────┴─────────┘
```

#### Tipos de Mensagem
- **HEARTBEAT**: Beacon periódico do Sink (assinado digitalmente)
- **DATA**: Dados de aplicação (autenticados via MAC)

### 🔄 Roteamento Multi-Hop

#### Seleção de Uplink
- Nodes escaneiam advertisements BLE
- Selecionam uplink com **menor hop count** para o Sink
- Advertisements incluem hop count no manufacturer data

#### Forwarding Table
- Cada Node mantém tabela de roteamento
- Mapeia NIDs de destino → conexão BLE do próximo salto
- Atualizada dinamicamente ao receber pacotes

#### Propagação de Heartbeats
- Sink envia heartbeat com hop=0
- Cada Node incrementa hop count ao reencaminhar
- Nodes atualizam seu hop count baseado no uplink

---

## � Como Usar

### 1. Gerar Certificados (Já existem no projeto)

```bash
cd support/pki_tools
python3 gen_certs.py
```

Isto gera:
- `certs/ca.crt` - Certificado da CA
- `certs/ca.key` - Chave privada da CA
- `certs/sink.crt` / `certs/sink.key` - Certificado/chave do Sink
- `certs/nodeA.crt` / `certs/nodeA.key` - Certificado/chave do Node A

### 2. Executar o Sink

```bash
python3 sink/main.py --cert certs/sink.crt --key certs/sink.key --ca certs/ca.crt
```

### 3. Executar um Node

```bash
python3 node/main.py --cert certs/nodeA.crt --key certs/nodeA.key --ca certs/ca.crt --sink-cert certs/sink.crt
```

### 4. Conectar Node ao Sink

No CLI do Node:
```
> scan
> connect 0
```

---

## 🔍 Estado Atual do Projeto

### ✅ Completamente Implementado
- [x] Handshake com autenticação mútua
- [x] Derivação de chaves de sessão via ECDH
- [x] Autenticação de pacotes via HMAC-SHA256
- [x] Proteção contra replay attacks
- [x] Heartbeat com assinatura digital
- [x] Deteção de perda de uplink
- [x] Roteamento multi-hop
- [x] Seleção automática de uplink
- [x] BLE GATT server/client em Nodes
- [x] Interface CLI para Nodes

### 📋 Por Fazer (Prioridades)

#### 🔴 CRÍTICO
- [ ] **Implementar DTLS End-to-End**
  - Segurança end-to-end entre Nodes e Sink
  - Proteção de dados em trânsito através de múltiplos hops
- [ ] **Fix: Sink crash quando Node se desliga**
  - Sink "tripa" quando um Node desconecta abruptamente
  - Implementar gestão robusta de desconexões
- [ ] **Fix: Ver oque se passa com a conexão/handshake as vezes é preciso tentar ligar 4-5 vezes para finalmente funcionar**

#### 🟠 ALTA
- [ ] **Implementar Inbox Service**
  - Criar serviço no Sink para receber mensagens
  - Display de mensagens com NID do remetente
  - Permitir Nodes enviar mensagens para o Sink
- [ ] **Verificar Heartbeat Timeout Chain**
  - Confirmar se propagação de timeouts está implementada
  - Testar cascata de desconexões em cadeia

#### 🟡 MÉDIA
- [ ] **Network Control para Simulação**
  - Adicionar controlo para simular perda de heartbeats
  - Permitir teste de resiliência em links específicos
- [x] ~~**Completar Informação da UI**~~
  - ~~Mostrar lista de downlinks e seus NIDs~~
  - ~~Display do contador de heartbeats perdidos~~
  - ~~Mostrar contador de mensagens roteadas~~

#### 🟢 EXTRAS
- [ ] **Suporte a Múltiplos Sinks**
  - Deteção automática de mudança de Sink
  - Renegociação de DTLS quando Sink atual deixa de ser válido
  - Failover automático entre Sinks
- [ ] **Revogação de Certificados**
  - Lista de NIDs/serials revogados
  - Distribuição via mensagens de controlo do Sink
  - Verificação de revogação antes de aceitar conexões
- [ ] **Rate Limiting por NID**
  - Mitigar flooding attacks
  - Proteção adicional contra replay dentro dos limites de MACs
  - Limites configuráveis por tipo de mensagem

## 🏗️ Arquitetura Técnica

### BLE GATT Service
- **Service UUID**: `12345678-1234-5678-1234-56789abcdef0`
- **RX Characteristic UUID**: `12345678-1234-5678-1234-56789abcdef1`
  - Propriedades: Write
  - Usado para receber pacotes via BLE

### Advertisement Format
```
Manufacturer Data (Company ID 0xFFFE):
┌──────┬──────────┬─────────────────┐
│ Hop  │ Reserved │ NID (16 bytes)  │
│ 1B   │ 1B       │                 │
└──────┴──────────┴─────────────────┘
```

### Fluxo de Conexão
1. Node escaneia advertisements BLE
2. Selecionamos Sink/Node com menor hop count
3. Conecta via BLE GATT
4. Inicia handshake TLS-style
5. Estabelece chave de sessão
6. Começa a receber heartbeats
7. Atualiza seu hop count e re-advertise

---

## 🔒 Modelo de Segurança

### Ameaças Mitigadas
- ✅ **Man-in-the-Middle**: Autenticação mútua via certificados
- ✅ **Replay Attacks**: Sequence numbers com verificação estrita
- ✅ **Packet Tampering**: HMAC-SHA256 em cada pacote
- ✅ **Impersonation**: Assinatura digital em heartbeats
- ✅ **Rogue Nodes**: Apenas nodes com certificados válidos podem conectar

### Ameaças Não Mitigadas
- ⚠️ **DoS via flooding**: Sem rate limiting implementado
- ⚠️ **Sybil attacks**: Sem limite de conexões por dispositivo
- ⚠️ **Physical attacks**: Sem proteção se chave privada for extraída

---

## 👥 Autores

Projeto desenvolvido no âmbito da disciplina de Segurança Informática e nas Comunicações.
