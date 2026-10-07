import os
import ast  # <-- AGORA SIM! Adicionamos a analise estatica de AST
import requests
from typing import TypedDict
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from langgraph.graph import StateGraph, END
from langchain_google_vertexai import ChatVertexAI  # Corrigido o import

app = FastAPI(title="Gerente Orquestrador IA - V3 (QA + AppSec com XAI Real)")

# ==========================================
# 1. A PRANCHETA DE TRABALHO (ESTADO)
# ==========================================
class Prancheta(TypedDict):
    estoria_usuario: str       # Corrigido snake_case
    plano_tecnico: str         # Corrigido
    codigo_gerado: str         # Corrigido
    testes_gerados: str        # Nova variavel de estado para QA
    comentarios_revisor: str
    aprovado: bool
    analise_estatica_ast: str  # <-- Rastreabilidade XAI real para o estado

# ==========================================
# AUXILIAR: ANALISADOR ESTÁTICO DE AST (O MÓDULO XAI)
# ==========================================
def executar_analise_estatica_ast(codigo: str) -> str:
    """
    Extrai a AST do codigo e busca de forma deterministica por padroes vulneraveis,
    fornecendo a rastreabilidade exata (XAI) de linhas e nos para o LLM.
    """
    if not codigo:
        return "Nenhum codigo disponivel para analise estatica."
        
    vulnerabilidades_encontradas = []
    try:
        # Faz o parsing do codigo bruto em uma arvore de sintaxe abstrata
        tree = ast.parse(codigo)
        
        # Percorre todos os nos da arvore
        for node in ast.walk(tree):
            # 1. Busca por chamadas de funcoes perigosas (e.g. Call: eval)
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == 'eval':
                    vulnerabilidades_encontradas.append(
                        f"[AST Call: eval()] detectada na Linha {node.lineno}. "
                        "Risco: Execucao de codigo arbitrario (Code Injection)."
                    )
            
            # 2. Busca por atribuicoes suspeitas de credenciais (e.g. Assign: USUARIO_CORRETO, SENHA)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        nome_var = target.id.upper()
                        if any(pat in nome_var for pat in ["PASSWORD", "SENHA", "SECRET", "CREDENTIAL", "TOKEN"]):
                            # Se o valor atribuido for uma string constante, ha risco de hardcode
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                vulnerabilidades_encontradas.append(
                                    f"[AST Assign: {target.id}] detectada na Linha {node.lineno}. "
                                    f"Valor estatico: '{node.value.value[:4]}...'. "
                                    "Risco: Credenciais expostas no codigo-fonte (OWASP A02:2021)."
                                )
                                
        if vulnerabilidades_encontradas:
            return "RESULTADOS DO ANALISADOR ESTÁTICO AST (XAI Real):\n" + "\n".join(vulnerabilidades_encontradas)
        return "RESULTADOS DO ANALISADOR ESTÁTICO AST: Nenhuma inconformidade deterministica encontrada na AST."
        
    except SyntaxError as e:
        return f"Erro de sintaxe ao gerar a AST (Linha {e.lineno}): {e.msg}"
    except Exception as e:
        return f"Falha no processamento da AST: {str(e)}"

# ==========================================
# 2. O CÉREBRO: GEMINI 2.5 FLASH
# ==========================================
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "fabrica-ia-squad-510502") # Corrigido variable naming
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
    Escreva APENAS o código final, sem explicações adicionais ou Markdown redundante fora do bloco de codigo."""
    
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
    
    # Executa a AST para injetar na revisao
    analise_ast = executar_analise_estatica_ast(estado['codigo_gerado'])
    
    prompt = f"""Você é um Especialista de Segurança de Aplicações (AppSec) e Tech Lead. 
    Audite a implementação principal e os testes gerados, considerando o relatório da analise estatica AST.

    Código Principal: 
    {estado['codigo_gerado']}

    Testes Unitários:
    {estado['testes_gerados']}

    Rastreabilidade e Fatos do Analisador Estático (Módulo XAI):
    {analise_ast}

    Regras de Validação de AppSec e Qualidade:
    1. OWASP Top 10: Busque ativamente por injeções, senhas hardcoded ou logs sensíveis.
    2. Com base na AST fornecida, aponte as linhas exatas e o tipo de nó (ex: Call, Assign) que contêm riscos.
    3. Tratamento de Exceções: O código lida com erros de forma segura sem expor a stack trace?

    Se TUDO estiver perfeitamente seguro e bem testado, responda APENAS a palavra 'APROVADO'.
    Se encontrar falhas, NÃO use a palavra APROVADO. Forneça uma explicação técnica embasada da causa raiz da vulnerabilidade, cite os nos e linhas exatas acusados na analise AST e como corrigi-la para que o Programador refaça o trabalho."""

    resposta = llm_cerebro.invoke(prompt).content

    if "APROVADO" in resposta.upper() and "RESULTADOS DO ANALISADOR" not in analise_ast:
        print("✅ [Revisor] Código e Testes Aprovados!")
        return {"aprovado": True, "comentarios_revisor": "Tudo certo.", "analise_estatica_ast": analise_ast}
    else:
        print(f"❌ [Revisor] Falhas encontradas: {resposta}")
        return {"aprovado": False, "comentarios_revisor": resposta, "analise_estatica_ast": analise_ast}

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
fluxograma.add_edge("Programador", "QA")
fluxograma.add_edge("QA", "Revisor")
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
    estoria_usuario: str      # Corrigido o nome do campo
    numero_pr: str = None     # Corrigido o nome do campo
    repositorio: str = "msimonae/Fabrica-IA-Squad"

@app.get("/")
def health_check():
    return {"status": "ok", "servico": "Gerente Orquestrador IA v3 - AST Habilitado"}

@app.post("/executar")
def executar_fluxo(requisicao: TarefaRequest):
    try:
        configuracao = {"recursion_limit": 8} # Corrigido parametro snake_case
        resultado = gerente_oficial.invoke({
            "estoria_usuario": requisicao.estoria_usuario,
            "aprovado": False
        }, configuracao)

        return {
            "plano_tecnico": resultado.get("plano_tecnico"),
            "codigo_gerado": resultado.get("codigo_gerado"),
            "testes_gerados": resultado.get("testes_gerados"),
            "analise_ast": resultado.get("analise_estatica_ast"),
            "aprovado": resultado.get("aprovado")
        }
    except Exception as e:
        if "Recursion" in e.__class__.__name__:
            raise HTTPException(status_code=408, detail="A Squad IA entrou em loop de validação AppSec/QA.")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/revisar_pr")  # Corrigido endpoint
def revisar_pr_direto(requisicao: TarefaRequest):
    token = os.environ.get("GITHUB_TOKEN") # Corrigido nome da variavel
    if not token or not requisicao.numero_pr:
        raise HTTPException(status_code=400, detail="Token ou número do PR ausentes.")
    
    try:
        url_diff = f"https://api.github.com/repos/{requisicao.repositorio}/pulls/{requisicao.numero_pr}"
        cabecalhos_diff = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3.diff"}
        resposta_diff = requests.get(url_diff, headers=cabecalhos_diff)
        codigo_alterado = resposta_diff.text

        # Executa analise real de AST sobre as linhas modificadas
        analise_ast = executar_analise_estatica_ast(codigo_alterado)

        prompt_revisor_avancado = f"""Você é um Inspetor de Segurança Sênior (AppSec).
        Analise o seguinte 'git diff' em busca de vulnerabilidades (OWASP Top 10) e correlacione as falhas com o relatorio de AST se disponivel.

        Código Alterado no PR:
        {codigo_alterado}

        Rastreabilidade do Analisador Estático (Módulo XAI):
        {analise_ast}

        Se o código for perfeitamente seguro e a AST nao indicar falhas, responda 'APROVADO'. 
        Se contiver falhas, use a rastreabilidade do AST (nós, linhas) e sugira a correção."""

        parecer = llm_cerebro.invoke(prompt_revisor_avancado).content
        aprovado = "APROVADO" in parecer.upper() and "RESULTADOS" not in analise_ast

        prompt_qa = f"""Baseado no seguinte diff de código, escreva uma suíte de testes unitários em pytest que valide este código:
        {codigo_alterado}
        Retorne apenas o código em Python."""

        testes_sugeridos = llm_cerebro.invoke(prompt_qa).content

        url_comentario = f"https://api.github.com/repos/{requisicao.repositorio}/issues/{requisicao.numero_pr}/comments"
        cabecalhos_comentario = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"}
        icone = "✅ APROVADO" if aprovado else "❌ FALHAS DE SEGURANÇA ENCONTRADAS"

        comentario_final = (
            f"### 🕵️ Auditoria AppSec Avançada\n**Status:** {icone}\n\n"
            f"**Análise Estática de Código (AST):\n{analise_ast}\n\n"
            f"**Análise Estrutural e de Segurança (IA):\n{parecer}\n\n"
            f"---\n### 🧪 Sugestão de Testes Unitários Automáticos (QA)\n{testes_sugeridos}"
        )

        requests.post(url_comentario, json={"body": comentario_final}, headers=cabecalhos_comentario)

        return {"status": "revisado", "aprovado": aprovado}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    porta = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=porta)
