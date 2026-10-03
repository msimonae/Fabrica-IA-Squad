from typing import TypedDict
from langgraph.graph import StateGraph, END
from langchain_google_vertexai import ChatAnthropicVertex

# ==========================================
# 1. A PRANCHETA DE TRABALHO (ESTADO)
# Aqui definimos os papéis que circulam na fábrica
# ==========================================
class Prancheta(TypedDict):
    estoria_usuario: str
    plano_tecnico: str
    codigo_gerado: str
    comentarios_revisor: str
    aprovado: bool

# ==========================================
# 2. O CÉREBRO: CLAUDE 3.5 SONNET
# ==========================================
# Conecta ao Claude 3.5 Sonnet hospedado com segurança no GCP
llm_claude = ChatAnthropicVertex(
    model_name="claude-3-5-sonnet@20240620",
    temperature=0.1 # Temperatura baixa: foca na lógica e não "inventa" código
)

# ==========================================
# 3. OS DEPARTAMENTOS (NÓS DA FÁBRICA)
# ==========================================
def departamento_arquiteto(estado: Prancheta):
    # Lê a estória e cria o plano
    prompt = f"Você é um Arquiteto de Software. Crie um plano técnico para: {estado['estoria_usuario']}"
    resposta = llm_claude.invoke(prompt)
    return {"plano_tecnico": resposta.content}

def departamento_programador(estado: Prancheta):
    # Lê o plano do arquiteto (ou a bronca do revisor) e escreve o código
    prompt = f"""Você é um Desenvolvedor Sênior. 
    Plano: {estado['plano_tecnico']}
    Erros anteriores para corrigir: {estado.get('comentarios_revisor', 'Nenhum erro ainda.')}
    Escreva APENAS o código final."""
    
    resposta = llm_claude.invoke(prompt)
    return {"codigo_gerado": resposta.content}

def departamento_revisor(estado: Prancheta):
    # Lê o código do programador e procura falhas de segurança
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
# O gerente olha a prancheta para decidir para onde o papel vai
def decidir_proximo_passo(estado: Prancheta):
    if estado["aprovado"] == True:
        return "Finalizar"
    else:
        return "Refazer"

# ==========================================
# 5. DESENHANDO O FLUXOGRAMA (O LANGGRAPH)
# ==========================================
fluxograma = StateGraph(Prancheta)

# Colocando as mesas na fábrica
fluxograma.add_node("Arquiteto", departamento_arquiteto)
fluxograma.add_node("Programador", departamento_programador)
fluxograma.add_node("Revisor", departamento_revisor)

# Definindo por onde o trabalho começa
fluxograma.set_entry_point("Arquiteto")

# Ligando as mesas com esteiras
fluxograma.add_edge("Arquiteto", "Programador")
fluxograma.add_edge("Programador", "Revisor")

# Adicionando o controle de qualidade (O Loop)
fluxograma.add_conditional_edges(
    "Revisor", # Quem passa a prancheta
    decidir_proximo_passo, # O gerente olha a regra
    {
        "Refazer": "Programador", # Se tiver erro, volta pro programador
        "Finalizar": END          # Se aprovado, joga na caixa de saída (Fim)
    }
)

# A fábrica está pronta
gerente_oficial = fluxograma.compile()
