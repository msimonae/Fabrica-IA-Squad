from typing import TypedDict
from langgraph.graph import StateGraph, END
from langchain_google_vertexai import ChatAnthropicVertex

# ==========================================
# 1. A PRANCHETA DE TRABALHO (ESTADO)
# ==========================================
class Prancheta(TypedDict):
    estoria_usuario: str
    plano_tecnico: str
    codigo_gerado: str
    comentarios_revisor: str
    aprovado: bool

# ==========================================
# 2. O CÉREBRO: CLAUDE 5.5 SONNET
# ==========================================
# Conecta à versão mais avançada para engenharia de software
llm_claude = ChatAnthropicVertex(
    model_name="claude-5-5-sonnet", # Atualizado para a versão 5.5
    temperature=0.1 # Mantido em 0.1 para máximo rigor lógico e previsibilidade
)

# ==========================================
# 3. OS DEPARTAMENTOS (NÓS DA FÁBRICA)
# ==========================================
def departamento_arquiteto(estado: Prancheta):
    prompt = f"Você é um Arquiteto de Software. Crie um plano técnico para: {estado['estoria_usuario']}"
    resposta = llm_claude.invoke(prompt)
    return {"plano_tecnico": resposta.content}

def departamento_programador(estado: Prancheta):
    prompt = f"""Você é um Desenvolvedor Sênior. 
    Plano: {estado['plano_tecnico']}
    Erros anteriores para corrigir: {estado.get('comentarios_revisor', 'Nenhum erro ainda.')}
    Escreva APENAS o código final."""
    
    resposta = llm_claude.invoke(prompt)
    return {"codigo_gerado": resposta.content}

def departamento_revisor(estado: Prancheta):
    prompt = f"""Você é um Inspetor de Segurança (AppSec). 
    Revise este código: {estado['codigo_gerado']}
    Se estiver perfeito e seguro, responda apenas 'APROVADO'.
    Se tiver erros, explique o erro detalhadamente."""
    
    resposta = llm_claude.invoke(prompt).content
    
    if "APROVADO" in resposta.upper():
        return {"aprovado": True, "comentarios_revisor": "Tudo certo."}
    else:
        return {"aprovado": False, "comentarios_revisor": resposta}

# ==========================================
# 4. A REGRA DE CONTROLE DE QUALIDADE
# ==========================================
def decidir_proximo_passo(estado: Prancheta):
    if estado["aprovado"] == True:
        return "Finalizar"
    else:
        return "Refazer"

# ==========================================
# 5. DESENHANDO O FLUXOGRAMA (O LANGGRAPH)
# ==========================================
fluxograma = StateGraph(Prancheta)

fluxograma.add_node("Arquiteto", departamento_arquiteto)
fluxograma.add_node("Programador", departamento_programador)
fluxograma.add_node("Revisor", departamento_revisor)

fluxograma.set_entry_point("Arquiteto")

fluxograma.add_edge("Arquiteto", "Programador")
fluxograma.add_edge("Programador", "Revisor")

fluxograma.add_conditional_edges(
    "Revisor", 
    decidir_proximo_passo, 
    {
        "Refazer": "Programador", 
        "Finalizar": END          
    }
)

gerente_oficial = fluxograma.compile()
