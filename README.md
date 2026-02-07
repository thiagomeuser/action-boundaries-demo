# Action Boundaries - Exemplo Prático em Python

## Visão Geral

Este exemplo demonstra como implementar **action boundaries** em agentes de IA de forma tecnicamente mandatória

## O Que o Código Demonstra

### 1. **Segregação de Roles**
Três agentes com responsabilidades distintas:
- **Planner**: Raciocínio e análise (read-only)
- **Executor**: Execução de ações (write em staging)
- **Validator**: Validação e auditoria (read-only)

### 2. **Enforcement Técnico**
```python
# NÃO É ISSO 
"Você é um planner, não execute ações"

# É ISSO
if context.role not in tool.allowed_roles:
    raise PermissionError("Role não autorizado")
```

### 3. **Camadas de Validação**
Cada execução passa por 4 layers de controle:
1. Tool existe no registry?
2. Role tem permissão?
3. Requer aprovação humana?
4. Rate limit respeitado?

### 4. **Audit Trail Completo**
Logs de todas as ações **e tentativas bloqueadas**:
```
[AUDIT] planner | analyze_data | {'data': 'vendas_q4'}
[BLOCKED] planner tentou 'execute_action' - Razão: role_violation
[AUDIT] executor | deploy_to_production | {'config': 'prod-v2'}
```

## Como Executar

```bash
python action_boundaries_example.py
```

## Cenários Demonstrados

| Cenário | Agente | Ação | Resultado | Razão |
|---------|--------|------|-----------|-------|
| 1 | Planner | Analisar dados | ✓ Permitido | Está em allowed_roles |
| 2 | Planner | Executar ação | ✗ Bloqueado | Violação de role |
| 3 | Executor | Executar em staging | ✓ Permitido | Dentro do escopo |
| 4 | Executor | Deploy sem aprovação | ✗ Bloqueado | Requer aprovação humana |
| 5 | Executor | Deploy com aprovação | ✓ Permitido | Aprovação presente |
| 6 | Validator | Validar output | ✓ Permitido | Função do validator |
| 7 | Validator | Executar ação | ✗ Bloqueado | Violação de role |

## Conceitos-Chave Implementados

### 1. Tool Registry com Policies
```python
Tool(
    name="deploy_to_production",
    function=deploy_func,
    allowed_roles=[AgentRole.EXECUTOR],      # Whitelist de roles
    requires_approval=True,                   # Human-in-the-loop
    can_modify_data=True,                     # Metadado de risco
    max_calls_per_minute=1                    # Rate limiting
)
```

### 2. Execution Context
```python
ExecutionContext(
    agent_id="executor-001",
    role=AgentRole.EXECUTOR,
    timestamp=datetime.now(),
    action="deploy_to_production",
    parameters={"config": "prod-v2"},
    approved_by="human-supervisor-123"        # Rastro de aprovação
)
```

### 3. Gateway de Execução
```python
def execute(self, tool_name: str, context: ExecutionContext, **params):
    # Validação técnica, não confia no agente
    if context.role not in tool.allowed_roles:
        raise PermissionError(...)
    
    if tool.requires_approval and not context.approved_by:
        raise PermissionError(...)
```
