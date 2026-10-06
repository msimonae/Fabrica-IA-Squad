import os
import requests
from typing import TypedDict
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from langgraph.graph import StateGraph, END
from langchain_google_vertexai import ChatVertexAI

app = FastAPI(title="Gerente Orquestrador IA - V3 (QA + AppSec)")

# ==========================================
# 1. A PRANCHETA DE TRABALHO (ESTADO)
# ==========================================
class Prancheta(TypedDict):
    estoria_usuario: str
    plano_tecnico: str
    codigo_gerado: str
    testes_gerados: str  # Nova variável de estado para QA
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
    print("💻 [Programador] Escrevendo o código principal...")
    prompt = f"""Você é um Desenvolvedor Sênior. 
    Plano: {estado['plano_tecnico']}
    Erros para corrigir das tentativas anteriores: {estado.get('comentarios_revisor', 'Nenhum.')}
    Escreva APENAS o código final, sem explicações adicionais."""
    
    resposta = llm_cerebro.invoke(prompt)
    return {"codigo_gerado": resposta.content}

def departamento_qa(estado: Prancheta):
    print("🧪 [QA] Gerando testes unitários automatizados...")
    prompt = f"""Você é um Engenheiro de QA Sênior especialista em testes automatizados.
    Escreva os testes unitários utilizando o framework 'pytest' para o seguinte código:
    
    {estado['codigo_gerado']}
    
    Gere testes que cubram os caminhos felizes, casos de borda e validação de exceções.
    Retorne APENAS o código de testes, sem explicações adicionais."""
    
    resposta = llm_cerebro.invoke(prompt)
    return {"testes_gerados": resposta.content}

def departamento_revisor(estado: Prancheta):
    print("🕵️ [Revisor AppSec] Auditoria de Segurança e Qualidade...")
    prompt = f"""Você é um Especialista de Segurança de Aplicações (AppSec) e Tech Lead. 
    Audite a implementação principal e os testes gerados.
    
    Código Principal: 
    {estado['codigo_gerado']}
    
    Testes Unitários:
    {estado['testes_gerados']}
    
    Regras de Validação de AppSec e Qualidade:
    1. OWASP Top 10: Busque ativamente por injeções (SQL, Command, eval), XSS, senhas hardcoded ou logs sensíveis.
    2. Sanitização Rigorosa: Todas as entradas são validadas e tipadas corretamente?
    3. Tratamento de Exceções: O código lida com erros de forma segura sem expor a stack trace?
    4. Qualidade da Cobertura: Os testes unitários provam que o código bloqueia inputs maliciosos?
    
    Se TUDO estiver perfeitamente seguro e bem testado, responda APENAS a palavra 'APROVADO'.
    Se encontrar falhas, NÃO use a palavra APROVADO. Forneça uma explicação técnica embasada da causa raiz da vulnerabilidade e como corrigi-la para que o Programador refaça o trabalho."""
    
    resposta = llm_cerebro.invoke(prompt).content
    
    if "APROVADO" in resposta.upper():
        print("✅ [Revisor] Código e Testes Aprovados!")
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
        print("🔄 Devolvendo para o Programador refazer código e testes...")
        return "Refazer"

# ==========================================
# 5. CONSTRUINDO O FLUXOGRAMA MULTI-AGENTE
# ==========================================
fluxograma = StateGraph(Prancheta)
fluxograma.add_node("Arquiteto", departamento_arquiteto)
fluxograma.add_node("Programador", departamento_programador)
fluxograma.add_node("QA", departamento_qa)
fluxograma.add_node("Revisor", departamento_revisor)

fluxograma.set_entry_point("Arquiteto")
fluxograma.add_edge("Arquiteto", "Programador")
fluxograma.add_edge("Programador", "QA")       # O Programador passa o código para o QA
fluxograma.add_edge("QA", "Revisor")           # O QA passa código e testes para o Revisor
fluxograma.add_conditional_edges(
    "Revisor",
    decidir_proximo_passo,
    {"Refazer": "Programador", "Finalizar": END} # Volta pro Programador em caso de falha
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
    return {"status": "ok", "servico": "Gerente Orquestrador IA v3"}

@app.post("/executar")
def executar_fluxo(requisicao: TarefaRequest):
    try:
        configuracao = {"recursion_limit": 8} # Limite aumentado devido à nova etapa de QA
        
        resultado = gerente_oficial.invoke({
            "estoria_usuario": requisicao.estoria_usuario,
            "aprovado": False
        }, configuracao)
        
        return {
            "plano_tecnico": resultado.get("plano_tecnico"),
            "codigo_gerado": resultado.get("codigo_gerado"),
            "testes_gerados": resultado.get("testes_gerados"),
            "aprovado": resultado.get("aprovado")
        }
    except Exception as e:
        if "Recursion" in e.__class__.__name__:
            raise HTTPException(status_code=408, detail="A Squad IA entrou em loop de validação AppSec/QA.")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/revisar_pr")
def revisar_pr_direto(requisicao: TarefaRequest):
    token = os.environ.get("GITHUB_TOKEN")
    if not token or not requisicao.numero_pr:
        raise HTTPException(status_code=400, detail="Token ou número do PR ausentes.")
        
    try:
        url_diff = f"https://api.github.com/repos/{requisicao.repositorio}/pulls/{requisicao.numero_pr}"
        cabecalhos_diff = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3.diff"}
        resposta_diff = requests.get(url_diff, headers=cabecalhos_diff)
        codigo_alterado = resposta_diff.text
        
        prompt_revisor_avancado = f"""Você é um Inspetor de Segurança Sênior (AppSec).
        Analise o seguinte 'git diff' (linhas com + foram adicionadas) em busca de vulnerabilidades (OWASP Top 10), lógica frágil e falta de tipagem segura.
        
        Código Alterado no PR:
        {codigo_alterado}
        
        Se o código for perfeitamente seguro e seguir princípios de arquitetura limpa, responda apenas a palavra 'APROVADO'. 
        Se contiver falhas, detalhe a causa raiz técnica e sugira a correção."""
        
        parecer = llm_cerebro.invoke(prompt_revisor_avancado).content
        aprovado = "APROVADO" in parecer.upper()
        
        prompt_qa = f"""Baseado no seguinte diff de código, escreva uma suíte de testes unitários em pytest que valide este código:
        {codigo_alterado}
        Retorne apenas o código em Python."""
        
        testes_sugeridos = llm_cerebro.invoke(prompt_qa).content
        
        url_comentario = f"https://api.github.com/repos/{requisicao.repositorio}/issues/{requisicao.numero_pr}/comments"
        cabecalhos_comentario = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"}
        icone = "✅ APROVADO" if aprovado else "❌ FALHAS DE SEGURANÇA ENCONTRADAS"
        
        comentario_final = (
            f"### 🕵️ Auditoria AppSec Avançada\n**Status:** {icone}\n\n"
            f"**Análise Estrutural e de Segurança:**\n{parecer}\n\n"
            f"---\n### 🧪 Sugestão de Testes Unitários Automáticos (QA)\nPara garantir a estabilidade em produção, considere adicionar estes testes ao repositório:\n{testes_sugeridos}"
        )
        
        requests.post(url_comentario, json={"body": comentario_final}, headers=cabecalhos_comentario)
        
        return {"status": "revisado", "aprovado": aprovado}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    porta = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=porta)
