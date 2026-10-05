import os
import requests
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
# 2. O CÉREBRO: GEMINI 2.5 FLASH
# ==========================================
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "fabrica-ia-squad-510502")
REGION = os.environ.get("GOOGLE_CLOUD_REGION", "us-central1")

llm_cerebro = ChatVertexAI(
    model_name="gemini-2.5-flash", 
    project=PROJECT_ID,
    location=REGION,
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
    numero_pr: str = None
    repositorio: str = "msimonae/Fabrica-IA-Squad"

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

@app.post("/revisar_pr")
def revisar_pr_direto(requisicao: TarefaRequest):
    token = os.environ.get("GITHUB_TOKEN")
    if not token or not requisicao.numero_pr:
        raise HTTPException(status_code=400, detail="Token ou número do PR ausentes.")
        
    try:
        # 1. Puxar o código do GitHub (formato DIFF)
        url_diff = f"https://api.github.com/repos/{requisicao.repositorio}/pulls/{requisicao.numero_pr}"
        cabecalhos_diff = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3.diff"}
        resposta_diff = requests.get(url_diff, headers=cabecalhos_diff)
        codigo_alterado = resposta_diff.text
        
        # 2. Mandar o LLM revisar o código real
        prompt = f"""Você é um Inspetor de Segurança Sênior (AppSec).
        Analise o seguinte 'git diff' (linhas com + foram adicionadas) e busque vulnerabilidades críticas (ex: eval, senhas expostas, injeções).
        
        Código Alterado no PR:
        {codigo_alterado}
        
        Se o código for perfeitamente seguro, responda apenas a palavra 'APROVADO'. 
        Se contiver falhas, não use a palavra aprovado. Explique o risco detalhadamente e mostre como corrigir."""
        
        parecer = llm_cerebro.invoke(prompt).content
        aprovado = "APROVADO" in parecer.upper()
        
        # 3. Postar o resultado de volta no GitHub
        url_comentario = f"https://api.github.com/repos/{requisicao.repositorio}/issues/{requisicao.numero_pr}/comments"
        cabecalhos_comentario = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"}
        icone = "✅ APROVADO" if aprovado else "❌ FALHAS DE SEGURANÇA ENCONTRADAS"
        comentario_final = f"### 🕵️ Parecer do Agente Revisor\n**Status:** {icone}\n\n**Detalhes da Análise do Código:**\n{parecer}"
        
        requests.post(url_comentario, json={"body": comentario_final}, headers=cabecalhos_comentario)
        
        return {"status": "revisado", "aprovado": aprovado}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    porta = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=porta)
