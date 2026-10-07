import os
import ast
import requests
from typing import TypedDict, List
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from langgraph.graph import StateGraph, END
from langchain_google_vertexai import ChatVertexAI

app = FastAPI(title="Gerente Orquestrador IA - V3 (Advanced QA & AST AppSec)")

# ==========================================
# 1. A PRANCHETA DE TRABALHO (ESTADO)
# ==========================================
class Prancheta(TypedDict):
    estoria_usuario: str
    plano_tecnico: str
    codigo_gerado: str
    testes_gerados: str
    comentarios_revisor: str
    aprovado: bool
    analise_estatica_ast: str

# =========================================================================
# 2. O MÓDULO XAI DE ANÁLISE ESTÁTICA AVANÇADA (SAST DETERMINÍSTICO COM AST)
# =========================================================================
class ASTSecurityScanner(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilidades: List[str] = []

    def visit_Call(self, node: ast.Call):
        # 1. Busca por Code Injection (Call: eval, exec, input)
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in ['eval', 'exec', 'input']:
                self.vulnerabilidades.append(
                    f"🛑 [A03:2021-Injection] Chamada perigosa '{func_name}()' na Linha {node.lineno}. "
                    "Risco: Execução de código arbitrário e não confiável."
                )
            
            # 2. Injeção de Comando de Sistema (os.system, os.popen, etc.)
            if func_name in ['system', 'popen'] or (isinstance(node.func, ast.Attribute) and node.func.attr in ['system', 'popen']):
                self.vulnerabilidades.append(
                    f"🛑 [A03:2021-Injection] Chamada 'os.{func_name if isinstance(node.func, ast.Name) else node.func.attr}()' na Linha {node.lineno}. "
                    "Risco: Execução de comandos do sistema operacional (Command Injection)."
                )

        # 3. Injeção de Comando via Subprocess (shell=True)
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in ['Popen', 'run', 'call', 'check_output']:
                # Analisa se foi passado o parâmetro shell=True
                for keyword in node.keywords:
                    if keyword.arg == 'shell':
                        if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                            self.vulnerabilidades.append(
                                f"🛑 [A03:2021-Injection] Uso de 'subprocess.{node.func.attr}(shell=True)' na Linha {node.lineno}. "
                                "Risco: Criação de subprocesso vulnerável a Shell Injection."
                            )

            # 4. Desserialização Insegura (pickle, marshal, yaml)
            if isinstance(node.func.value, ast.Name) and node.func.value.id in ['pickle', 'marshal', 'yaml', 'shelve']:
                if node.func.attr in ['loads', 'load', 'unsafe_load']:
                    # Exceção para yaml se usar safe_load
                    if not (node.func.value.id == 'yaml' and node.func.attr == 'safe_load'):
                        self.vulnerabilidades.append(
                            f"🛑 [A08:2021-Integridade] Desserialização insegura '{node.func.value.id}.{node.func.attr}()' na Linha {node.lineno}. "
                            "Risco: Deserialização de dados não confiáveis pode levar à execução de código remoto (RCE)."
                        )

            # 5. Criptografia / Hashes Fracos
            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'hashlib':
                if node.func.attr in ['md5', 'sha1']:
                    self.vulnerabilidades.append(
                        f"⚠️ [A02:2021-Criptografia] Algoritmo de hash fraco 'hashlib.{node.func.attr}()' na Linha {node.lineno}. "
                        "Risco: Algoritmo suscetível a colisões. Use SHA-256 ou superior."
                    )

            # 6. Risco de SQL Injection
            # Procura por métodos como .execute() que realizem interpolação de strings
            if node.func.attr in ['execute', 'executemany']:
                if node.args:
                    primeiro_arg = node.args[0]
                    # Se o primeiro argumento da consulta for f-string, concatenação ou .format()
                    if (isinstance(primeiro_arg, ast.JoinedStr) or 
                        (isinstance(primeiro_arg, ast.BinOp) and isinstance(primeiro_arg.op, ast.Mod)) or
                        (isinstance(primeiro_arg, ast.Call) and isinstance(primeiro_arg.func, ast.Attribute) and primeiro_arg.func.attr == 'format')):
                        self.vulnerabilidades.append(
                            f"🛑 [A03:2021-Injection] Potencial SQL Injection na Linha {node.lineno} (chamada '.{node.func.attr}()'). "
                            "Risco: Consulta SQL construída dinamicamente com interpolação ou concatenação de strings. Utilize consultas parametrizadas."
                        )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # 7. Busca por Vazamento de Dados Sensíveis (Credenciais/Tokens)
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.upper()
                # Verifica se o nome da variável é sensível e possui valor de string constante
                if any(k in var_name for k in ["PASSWORD", "SENHA", "SECRET", "CREDENTIAL", "TOKEN", "API_KEY", "JWT"]):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        # Desconsidera strings de placeholders óbvias
                        if len(node.value.value) > 4 and not any(p in node.value.value.upper() for p in ["YOUR", "ENV", "PLACEHOLDER", "INSERT"]):
                            self.vulnerabilidades.append(
                                f"🛑 [A02:2021-Criptografia] Vazamento de Dados Sensíveis na Linha {node.lineno}. "
                                f"A variável '{target.id}' aparenta conter um valor confidencial estático (hardcoded)."
                            )
        self.generic_visit(node)

def executar_analise_estatica_ast(codigo: str) -> str:
    if not codigo:
        return "Nenhum código disponível para análise estática."
    try:
        # Resolve markdown ou blocos de código
        codigo_limpo = codigo.replace("```python", "").replace("```", "")
        tree = ast.parse(codigo_limpo)
        scanner = ASTSecurityScanner()
        scanner.visit(tree)
        
        if scanner.vulnerabilidades:
            return "RESULTADOS DO ANALISADOR ESTÁTICO AST (XAI Real):\n" + "\n".join(scanner.vulnerabilidades)
        return "RESULTADOS DO ANALISADOR ESTÁTICO AST: Nenhuma inconformidade determinística encontrada na AST."
    except SyntaxError as e:
        return f"Erro de sintaxe ao gerar a AST (Linha {e.lineno}): {e.msg}"
    except Exception as e:
        return f"Falha no processamento da AST: {str(e)}"

# ==========================================
# 3. O CÉREBRO: GEMINI 2.5 FLASH
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
# 4. OS DEPARTAMENTOS (NÓS DA FÁBRICA)
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
    
    # Executa a AST para injetar na revisão
    analise_ast = executar_analise_estatica_ast(estado['codigo_gerado'])
    
    prompt = f"""Você é um Especialista de Segurança de Aplicações (AppSec) e Tech Lead. 
    Audite a implementação principal e os testes gerados, considerando o relatório da análise estática AST.

    Código Principal: 
    {estado['codigo_gerado']}

    Testes Unitários:
    {estado['testes_gerados']}

    Rastreabilidade e Fatos do Analisador Estático (Módulo XAI):
    {analise_ast}

    Regras de Validação de AppSec e Qualidade:
    1. OWASP Top 10: Busque ativamente por injeções (SQL, Command, eval), XSS, senhas hardcoded ou logs sensíveis.
    2. Com base na AST fornecida, aponte as linhas exatas e o tipo de nó (ex: Call, Assign) que contêm riscos.
    3. Tratamento de Exceções: O código lida com erros de forma segura sem expor a stack trace?
    4. Qualidade da Cobertura: Os testes unitários provam que o código bloqueia inputs maliciosos?

    Se TUDO estiver perfeitamente seguro e bem testado, e o relatório da AST não acusar inconformidades, responda APENAS a palavra 'APROVADO'.
    Se encontrar falhas, NÃO use a palavra APROVADO. Forneça uma explicação técnica embasada da causa raiz da vulnerabilidade, cite os nós e linhas exatas acusados na análise AST e como corrigi-la para que o Programador refaça o trabalho."""

    resposta = llm_cerebro.invoke(prompt).content

    if "APROVADO" in resposta.upper() and "🛑" not in analise_ast:
        print("✅ [Revisor] Código e Testes Aprovados!")
        return {"aprovado": True, "comentarios_revisor": "Tudo certo.", "analise_estatica_ast": analise_ast}
    else:
        print(f"❌ [Revisor] Falhas encontradas: {resposta}")
        return {"aprovado": False, "comentarios_revisor": resposta, "analise_estatica_ast": analise_ast}

# ==========================================
# 5. A REGRA DE CONTROLE DE QUALIDADE
# ==========================================
def decidir_proximo_passo(estado: Prancheta):
    if estado.get("aprovado") is True:
        return "Finalizar"
    else:
        print("🔄 Devolvendo para o Programador refazer código e testes...")
        return "Refazer"

# ==========================================
# 6. CONSTRUINDO O FLUXOGRAMA MULTI-AGENTE
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
# 7. ENDPOINTS HTTP PARA O CLOUD RUN
# ==========================================
class TarefaRequest(BaseModel):
    estoria_usuario: str
    numero_pr: str = None
    repositorio: str = "msimonae/Fabrica-IA-Squad"

@app.get("/")
def health_check():
    return {"status": "ok", "servico": "Gerente Orquestrador IA v3 - Advanced AppSec AST"}

@app.post("/executar")
def executar_fluxo(requisicao: TarefaRequest):
    try:
        configuracao = {"recursion_limit": 8}
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

        # Executa análise de AST
        analise_ast = executar_analise_estatica_ast(codigo_alterado)

        prompt_revisor_avancado = f"""Você é um Inspetor de Segurança Sênior (AppSec).
        Analise o seguinte 'git diff' em busca de vulnerabilidades (OWASP Top 10) e correlacione as falhas com o relatório de AST se disponível.

        Código Alterado no PR:
        {codigo_alterado}

        Rastreabilidade do Analisador Estático (Módulo XAI):
        {analise_ast}

        Se o código for perfeitamente seguro e a AST nao indicar falhas, responda 'APROVADO'. 
        Se contiver falhas, use a rastreabilidade do AST (nós, linhas) e sugira a correção."""

        parecer = llm_cerebro.invoke(prompt_revisor_avancado).content
        aprovado = "APROVADO" in parecer.upper() and "🛑" not in analise_ast

        prompt_qa = f"""Baseado no seguinte diff de código, escreva uma suíte de testes unitários em pytest que valide este código:
        {codigo_alterado}
        Retorne apenas o código em Python."""

        testes_sugeridos = llm_cerebro.invoke(prompt_qa).content

        url_comentario = f"https://api.github.com/repos/{requisitorio}/issues/{requisicao.numero_pr}/comments"
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
