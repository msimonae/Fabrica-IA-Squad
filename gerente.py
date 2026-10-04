import os
from typing import TypedDict
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from langgraph.graph import StateGraph, END
from langchain_google_vertexai import ChatVertexAI

app = FastAPI(title="Gerente Orquestrador IA")

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
# 2. O CÉREBRO: GEMINI 1.5 FLASH
# ==========================================
llm_cerebro = ChatVertexAI(
    model_name="gemini-1.5-flash",
    temperature=0.1
)

# ==========================================
# 3. OS DEPARTAMENTOS (NÓS DA FÁBRICA)
# ==========================================
def departamento_arquiteto(estado: Prancheta):
    print("👷 [Arquiteto] Planejando a solução...")
    prompt = f"Você é um Arquiteto de Software. Crie um plano técnico conciso para: {estado['estoria_usuario']}"
    resposta = llm_cerebro.invoke(prompt)
    return {"plano_tecnico": resposta.content}

def departamento_programador(estado: Prancheta):
    print("💻 [Programador] Escrevendo o código...")
    prompt = f"""Você é um Desenvolvedor Sênior. 
    Plano: {estado['plano_tecnico']}
    Erros para corrigir: {estado.get('comentarios_revisor', 'Nenhum.')}
    Escreva APENAS o código final, sem explicações adicionais."""
    
    resposta = llm_cerebro.invoke(prompt)
    return {"codigo_gerado": resposta.content}

def departamento_revisor(estado: Prancheta):
    print("🕵️ [Revisor] Analisando segurança e qualidade...")
    prompt = f"""Você é um Inspetor de Segurança (AppSec). 
    Revise este código: {estado['codigo_gerado']}
    Se estiver perfeito, seguro e seguir boas práticas, responda APENAS a palavra 'APROVADO'.
    Se tiver erros, não use a palavra APROVADO. Explique o erro de forma direta."""
    
    resposta = llm_cerebro.invoke(prompt).content
    
    if "APROVADO" in resposta.upper():
        print("✅ [Revisor] Código Aprovado!")
        return {"aprovado": True, "comentarios_revisor": "Tudo certo."}
    else:
        print(f"❌ [Revisor] Falhas encontradas: {resposta}")
        return {"aprovado": False, "comentarios_revisor": resposta}

# ==========================================
# 4. A REGRA DE CONTROLE DE QUALIDADE
# ==========================================
def decidir_proximo_passo(estado: Prancheta):
    if estado.get("aprovado") is True:
        return "Finalizar"
    else:
        print("🔄 Devolvendo para o Programador refazer...")
        return "Refazer"

# ==========================================
# 5. CONSTRUINDO O FLUXOGRAMA
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
    {"Refazer": "Programador", "Finalizar": END}
)

gerente_oficial = fluxograma.compile()

# ==========================================
# 6. ENDPOINTS HTTP PARA O CLOUD RUN
# ==========================================
class TarefaRequest(BaseModel):
    estoria_usuario: str

@app.get("/")
def health_check():
    return {"status": "ok", "servico": "Gerente Orquestrador IA"}

@app.post("/executar")
def executar_fluxo(requisicao: TarefaRequest):
    try:
        resultado = gerente_oficial.invoke({
            "estoria_usuario": requisicao.estoria_usuario,
            "aprovado": False
        })
        return {
            "plano_tecnico": resultado.get("plano_tecnico"),
            "codigo_gerado": resultado.get("codigo_gerado"),
            "aprovado": resultado.get("aprovado")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    porta = int(os.environ.get("PORT", 8080))
    uvicorn.run("gerente:app", host="0.0.0.0", port=porta)
