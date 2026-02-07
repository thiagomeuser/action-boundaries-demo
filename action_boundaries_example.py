"""
Action Boundaries Implementation Example
Demonstração prática de como implementar segregação de escopo funcional em agentes de IA
"""

from typing import List, Dict, Any, Callable
from dataclasses import dataclass
from enum import Enum
import json
from datetime import datetime


# ============================================================================
# EXEMPLO 1: SEM ACTION BOUNDARIES (Anti-pattern)
# ============================================================================

class MonolithicAgent:
    """
    Agente monolítico com todas as capacidades concentradas.
    PROBLEMA: Pode raciocinar, executar e validar simultaneamente.
    """
    
    def __init__(self, db_connection, api_credentials):
        self.db = db_connection
        self.api_creds = api_credentials
        self.tools = self._load_all_tools()
    
    def _load_all_tools(self):
        """Acesso irrestrito a todas as ferramentas do sistema"""
        return {
            'read_user_data': self._read_user_data,
            'write_database': self._write_database,
            'call_external_api': self._call_external_api,
            'delete_records': self._delete_records,
            'modify_permissions': self._modify_permissions,
            'execute_sql': self._execute_sql,
        }
    
    def process(self, task: str):
        """
        Processa qualquer tarefa com acesso total.
        RISCO: Comportamento emergente imprevisível.
        """
        # O agente "decide" quais ferramentas usar baseado no prompt
        # Não há validação técnica do que ele pode ou não fazer
        plan = self._generate_plan(task)
        
        for step in plan:
            tool_name = step['tool']
            # PROBLEMA: Se o agente "aprender" o nome da ferramenta, ele pode usá-la
            if tool_name in self.tools:
                result = self.tools[tool_name](**step['params'])
                # Nenhuma validação de privilégios ou escopo


# ============================================================================
# EXEMPLO 2: COM ACTION BOUNDARIES (Pattern correto)
# ============================================================================

class AgentRole(Enum):
    """Roles com responsabilidades claramente definidas"""
    PLANNER = "planner"
    EXECUTOR = "executor"
    VALIDATOR = "validator"


@dataclass
class Tool:
    """Ferramenta com metadados de segurança"""
    name: str
    function: Callable
    allowed_roles: List[AgentRole]
    requires_approval: bool
    can_modify_data: bool
    max_calls_per_minute: int


@dataclass
class ExecutionContext:
    """Contexto de execução com tracking completo"""
    agent_id: str
    role: AgentRole
    timestamp: datetime
    action: str
    parameters: Dict[str, Any]
    approved_by: str = None


class ToolRegistry:
    """
    Registry central de ferramentas com controle de acesso.
    ENFORCEMENT: Validação técnica de permissões.
    """
    
    def __init__(self):
        self.tools: Dict[str, Tool] = {}
        self.audit_log: List[ExecutionContext] = []
    
    def register_tool(self, tool: Tool):
        """Registra ferramenta com policies explícitas"""
        self.tools[tool.name] = tool
    
    def can_execute(self, tool_name: str, role: AgentRole) -> bool:
        """Validação server-side de permissões"""
        if tool_name not in self.tools:
            return False
        
        tool = self.tools[tool_name]
        return role in tool.allowed_roles
    
    def execute(self, tool_name: str, context: ExecutionContext, **params) -> Any:
        """
        Gateway de execução com validação em múltiplas camadas.
        Não depende de prompt - valida tecnicamente.
        """
        # Layer 1: Tool existe?
        if tool_name not in self.tools:
            raise PermissionError(f"Tool '{tool_name}' não existe no registry")
        
        tool = self.tools[tool_name]
        
        # Layer 2: Role tem permissão?
        if context.role not in tool.allowed_roles:
            self._log_blocked_attempt(context, tool_name, "role_violation")
            raise PermissionError(
                f"Role '{context.role.value}' não pode executar '{tool_name}'. "
                f"Roles permitidos: {[r.value for r in tool.allowed_roles]}"
            )
        
        # Layer 3: Requer aprovação?
        if tool.requires_approval and not context.approved_by:
            self._log_blocked_attempt(context, tool_name, "missing_approval")
            raise PermissionError(f"Tool '{tool_name}' requer aprovação humana")
        
        # Layer 4: Rate limiting
        if not self._check_rate_limit(context.agent_id, tool_name, tool.max_calls_per_minute):
            self._log_blocked_attempt(context, tool_name, "rate_limit")
            raise PermissionError(f"Rate limit excedido para '{tool_name}'")
        
        # Execução com audit trail
        self._log_execution(context, tool_name, params)
        return tool.function(**params)
    
    def _check_rate_limit(self, agent_id: str, tool_name: str, max_per_minute: int) -> bool:
        """
        Verifica rate limiting por agente e ferramenta.
        Em produção, implementaria com Redis ou similar.
        """
        # Simplificado para exemplo - em produção seria mais sofisticado
        return True
    
    def _log_execution(self, context: ExecutionContext, tool: str, params: Dict):
        """Audit log completo"""
        context.action = tool
        context.parameters = params
        self.audit_log.append(context)
        print(f"[AUDIT] {context.role.value} | {tool} | {params}")
    
    def _log_blocked_attempt(self, context: ExecutionContext, tool: str, reason: str):
        """Log de tentativas bloqueadas - crítico para segurança"""
        print(f"[BLOCKED] {context.role.value} tentou '{tool}' - Razão: {reason}")
        self.audit_log.append(context)


class BoundedAgent:
    """
    Agente com boundaries mandatórios.
    PRINCÍPIO: Só pode fazer o que está explicitamente permitido.
    """
    
    def __init__(self, agent_id: str, role: AgentRole, registry: ToolRegistry):
        self.agent_id = agent_id
        self.role = role
        self.registry = registry
        self._validate_role_setup()
    
    def _validate_role_setup(self):
        """Validação na inicialização"""
        print(f"[INIT] Agente '{self.agent_id}' inicializado com role '{self.role.value}'")
    
    def execute_tool(self, tool_name: str, approved_by: str = None, **params) -> Any:
        """
        Único ponto de execução - passa pelo gateway.
        NÃO HÁ ACESSO DIRETO ÀS FERRAMENTAS.
        """
        context = ExecutionContext(
            agent_id=self.agent_id,
            role=self.role,
            timestamp=datetime.now(),
            action=tool_name,
            parameters=params,
            approved_by=approved_by
        )
        
        return self.registry.execute(tool_name, context, **params)


# ============================================================================
# SETUP DE FERRAMENTAS COM BOUNDARIES
# ============================================================================

def setup_tools_with_boundaries() -> ToolRegistry:
    """
    Configuração de ferramentas com segregação explícita.
    CRÍTICO: Policies são código, não prompt.
    """
    registry = ToolRegistry()
    
    # Tool 1: Análise (read-only)
    registry.register_tool(Tool(
        name="analyze_data",
        function=lambda data: f"Análise de: {data}",
        allowed_roles=[AgentRole.PLANNER],  # Apenas planner
        requires_approval=False,
        can_modify_data=False,
        max_calls_per_minute=100
    ))
    
    # Tool 2: Leitura de dados
    registry.register_tool(Tool(
        name="read_database",
        function=lambda query: f"Dados: {query}",
        allowed_roles=[AgentRole.PLANNER, AgentRole.VALIDATOR],  # Não executor
        requires_approval=False,
        can_modify_data=False,
        max_calls_per_minute=50
    ))
    
    # Tool 3: Execução de ações (staging)
    registry.register_tool(Tool(
        name="execute_action",
        function=lambda action: f"Executando: {action}",
        allowed_roles=[AgentRole.EXECUTOR],  # Apenas executor
        requires_approval=False,
        can_modify_data=True,
        max_calls_per_minute=10
    ))
    
    # Tool 4: Deploy em produção (crítico)
    registry.register_tool(Tool(
        name="deploy_to_production",
        function=lambda config: f"Deploy: {config}",
        allowed_roles=[AgentRole.EXECUTOR],  # Apenas executor
        requires_approval=True,  # REQUER APROVAÇÃO HUMANA
        can_modify_data=True,
        max_calls_per_minute=1
    ))
    
    # Tool 5: Validação
    registry.register_tool(Tool(
        name="validate_output",
        function=lambda output: f"Validado: {output}",
        allowed_roles=[AgentRole.VALIDATOR],  # Apenas validator
        requires_approval=False,
        can_modify_data=False,
        max_calls_per_minute=100
    ))
    
    return registry


# ============================================================================
# DEMONSTRAÇÃO PRÁTICA
# ============================================================================

def demonstrate_action_boundaries():
    """
    Demonstra a diferença entre agentes com e sem boundaries.
    """
    print("="*80)
    print("DEMONSTRAÇÃO: ACTION BOUNDARIES EM AGENTES DE IA")
    print("="*80)
    print()
    
    # Setup
    registry = setup_tools_with_boundaries()
    
    # Criar agentes com roles diferentes
    planner = BoundedAgent("planner-001", AgentRole.PLANNER, registry)
    executor = BoundedAgent("executor-001", AgentRole.EXECUTOR, registry)
    validator = BoundedAgent("validator-001", AgentRole.VALIDATOR, registry)
    
    print()
    print("-"*80)
    print("CENÁRIO 1: Planner tentando analisar dados (PERMITIDO)")
    print("-"*80)
    try:
        result = planner.execute_tool("analyze_data", data="vendas_q4")
        print(f"✓ Sucesso: {result}")
    except PermissionError as e:
        print(f"✗ Bloqueado: {e}")
    
    print()
    print("-"*80)
    print("CENÁRIO 2: Planner tentando executar ação (BLOQUEADO)")
    print("-"*80)
    try:
        result = planner.execute_tool("execute_action", action="delete_records")
        print(f"✓ Sucesso: {result}")
    except PermissionError as e:
        print(f"✗ Bloqueado: {e}")
    
    print()
    print("-"*80)
    print("CENÁRIO 3: Executor executando ação em staging (PERMITIDO)")
    print("-"*80)
    try:
        result = executor.execute_tool("execute_action", action="update_config")
        print(f"✓ Sucesso: {result}")
    except PermissionError as e:
        print(f"✗ Bloqueado: {e}")
    
    print()
    print("-"*80)
    print("CENÁRIO 4: Executor tentando deploy sem aprovação (BLOQUEADO)")
    print("-"*80)
    try:
        result = executor.execute_tool("deploy_to_production", config="prod-v2")
        print(f"✓ Sucesso: {result}")
    except PermissionError as e:
        print(f"✗ Bloqueado: {e}")
    
    print()
    print("-"*80)
    print("CENÁRIO 5: Executor fazendo deploy com aprovação humana (PERMITIDO)")
    print("-"*80)
    try:
        result = executor.execute_tool(
            "deploy_to_production", 
            approved_by="human-supervisor-123",
            config="prod-v2"
        )
        print(f"✓ Sucesso: {result}")
    except PermissionError as e:
        print(f"✗ Bloqueado: {e}")
    
    print()
    print("-"*80)
    print("CENÁRIO 6: Validator validando output (PERMITIDO)")
    print("-"*80)
    try:
        result = validator.execute_tool("validate_output", output="resultado_X")
        print(f"✓ Sucesso: {result}")
    except PermissionError as e:
        print(f"✗ Bloqueado: {e}")
    
    print()
    print("-"*80)
    print("CENÁRIO 7: Validator tentando executar ação (BLOQUEADO)")
    print("-"*80)
    try:
        result = validator.execute_tool("execute_action", action="modify_data")
        print(f"✓ Sucesso: {result}")
    except PermissionError as e:
        print(f"✗ Bloqueado: {e}")
    
    print()
    print("="*80)
    print("AUDIT LOG COMPLETO")
    print("="*80)
    for entry in registry.audit_log:
        print(f"{entry.timestamp.strftime('%H:%M:%S')} | "
              f"{entry.role.value:12} | "
              f"{entry.agent_id:15} | "
              f"{entry.action}")
    
    print()
    print("="*80)
    print("PRINCÍPIOS DEMONSTRADOS:")
    print("="*80)
    print("✓ Segregação de roles mandatórios tecnicamente")
    print("✓ Validação server-side, não baseada em prompt")
    print("✓ Audit trail completo de execuções e tentativas bloqueadas")
    print("✓ Human-in-the-loop para ações críticas")
    print("✓ Rate limiting por ferramenta")
    print("✓ Impossibilidade de privilege escalation")
    print()


if __name__ == "__main__":
    demonstrate_action_boundaries()
