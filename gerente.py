import os
import ast
import re
import requests
from typing import TypedDict, List
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from langgraph.graph import StateGraph, END
from langchain_google_vertexai import ChatVertexAI

from context_layer import GraphRAGBuilder

app = FastAPI(title="Gerente Orquestrador IA - V4.3 (Zero-Trust DevSecOps)")

# ==========================================
# 1. A PRANCHETA DE TRABALHO (ESTADO)
# ==========================================
class Prancheta(TypedDict):
    estoria_usuario: str
    plano_tecnico: str
    codigo_backend: str       
    codigo_frontend: str      
    testes_gerados: str       
    comentarios_revisor: str
    aprovado: bool
    analise_estatica_ast: str 

# ---------------------------------------------------------
# CORREÇÃO: Lazy Loading do Cérebro (Evita Crash no Boot)
# ---------------------------------------------------------
def get_llm():
    PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "fabrica-ia-squad-510502")
    REGION = os.environ.get("GOOGLE_CLOUD_REGION", "us-central1")
    return ChatVertexAI(
        model_name="gemini-2.5-flash", 
        project=PROJECT_ID,
        location=REGION,
        temperature=0.1
    )

# =========================================================================
# 2. O MÓDULO XAI DE ANÁLISE ESTÁTICA AVANÇADA (SAST POLIGLOTA)
# =========================================================================
class ASTSecurityScanner(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilidades: List[str] = []

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in ['eval', 'exec', 'input']:
                self.vulnerabilidades.append(
                    f"🛑 [A03:2021-Injection (Backend)] Chamada perigosa '{func_name}()' na Linha {node.lineno}. Risco: Execução de código arbitrário."
                )
            if func_name in ['system', 'popen'] or (isinstance(node.func, ast.Attribute) and node.func.attr in ['system', 'popen']):
                self.vulnerabilidades.append(
                    f"🛑 [A03:2021-Injection (Backend)] Chamada 'os.{func_name if isinstance(node.func, ast.Name) else node.func.attr}()' na Linha {node.lineno}. Risco: Command Injection."
                )
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in ['Popen', 'run', 'call', 'check_output']:
                for keyword in node.keywords:
                    if keyword.arg == 'shell':
                        if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                            self.vulnerabilidades.append(f"🛑 [A03:2021-Injection (Backend)] Uso de subprocess com shell=True Linha {node.lineno}. Risco: Shell Injection.")
            
            if isinstance(node.func.value, ast.Name) and node.func.value.id in ['pickle', 'marshal', 'yaml', 'shelve']:
                if node.func.attr in ['loads', 'load', 'unsafe_load']:
                    if not (node.func.value.id == 'yaml' and node.func.attr == 'safe_load'):
                        self.vulnerabilidades.append(f"🛑 [A08:2021-Integridade (Backend)] Desserialização insegura na Linha {node.lineno}.")

            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'hashlib':
                if node.func.attr in ['md5', 'sha1']:
                    self.vulnerabilidades.append(f"⚠️ [A02:2021-Criptografia] Algoritmo de hash fraco na Linha {node.lineno}.")

            if node.func.attr in ['execute', 'executemany']:
                if node.args:
                    primeiro_arg = node.args[0]
                    if (isinstance(primeiro_arg, ast.JoinedStr) or 
                        (isinstance(primeiro_arg, ast.BinOp) and isinstance(primeiro_arg.op, ast.Mod)) or
                        (isinstance(primeiro_arg, ast.Call) and isinstance(primeiro_arg.func, ast.Attribute) and primeiro_arg.func.attr == 'format')):
                        self.vulnerabilidades.append(f"🛑 [A03:2021-Injection (Backend)] Potencial SQL Injection na Linha {node.lineno}.")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.upper()
                if any(k in var_name for k in ["PASSWORD", "SENHA", "SECRET", "CREDENTIAL", "TOKEN", "API_KEY", "JWT"]):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if len(node.value.value) > 4 and not any(p in node.value.value.upper() for p in ["YOUR", "ENV", "PLACEHOLDER", "INSERT"]):
                            self.vulnerabilidades.append(f"🛑 [A02:2021-Criptografia] Vazamento de Dados Sensíveis na Linha {node.lineno}.")
        self.generic_visit(node)

class FrontendSecurityScanner:
    def __init__(self):
        self.vulnerabilidades: List[str] = []

    def scan_code(self, code: str):
        if not code: return
        if re.search(r'dangerouslySetInnerHTML|\.innerHTML\s*=', code):
            self.vulnerabilidades.append("🛑 [A03:2021-Injection (Frontend)] Uso de 'innerHTML' detectado. Risco: DOM XSS.")
        if re.search(r'\beval\(|setTimeout\s*\(\s*["\']', code):
            self.vulnerabilidades.append("🛑 [A03:2021-Injection (Frontend)] Uso de eval() ou setTimeout com strings.")
        if re.search(r'(localStorage|sessionStorage)\.setItem\s*\(', code):
            if any(key in code.upper() for key in ["TOKEN", "JWT", "PASSWORD", "SENHA", "CREDENTIAL", "SECRET"]):
                self.vulnerabilidades.append("⚠️ [A04:2021-Design Inseguro] Uso de web storage para persistência confidencial. Evite expor tokens JWT aqui.")
        if "bypassSecurityTrust" in code:
            self.vulnerabilidades.append("⚠️ [A03:2021-Injection (Frontend)] Desativação intencional de blindagem XSS.")
        
        match_secret = re.findall(r'(?:API_KEY|TOKEN|SECRET|PASSWORD|JWT|SENHA)\s*=\s*["\']([^"\'{}[\]\s]{8,})["\']', code, re.IGNORECASE)
        if match_secret:
            for segredo in match_secret:
                if not any(placeholder in segredo.upper() for placeholder in ["ENV", "PLACEHOLDER", "INSERT", "YOUR", "PROCESS", "REPLACE"]):
                    self.vulnerabilidades.append("🛑 [A02:2021-Criptografia] Potencial vazamento de credencial estática no frontend.")

def executar_analise_estatica_hibrida(codigo_backend: str, codigo_frontend: str) -> str:
    relatorio = []
    
    # 1. Validação do Backend (AST) - Alterado o filtro de checagem
    if codigo_backend and len(codigo_backend.strip()) > 10: 
        try:
            codigo_limpo_back = codigo_backend.replace("```python", "").replace("```", "")
            tree = ast.parse(codigo_limpo_back)
            scanner_back = ASTSecurityScanner()
            scanner_back.visit(tree)
            if scanner_back.vulnerabilidades:
                relatorio.append("🔍 BACKEND (Python AST):\n" + "\n".join(scanner_back.vulnerabilidades))
            else:
                relatorio.append("✅ BACKEND (Python AST): Nenhuma inconformidade determinística detectada.")
        except SyntaxError as e:
            relatorio.append(f"❌ BACKEND Erro de Sintaxe (Linha {e.lineno}): {e.msg}")
        except Exception as e:
            relatorio.append(f"❌ BACKEND Falha interna do Scanner AST: {str(e)}")
    else:
         relatorio.append("⚠️ BACKEND: Nenhum código processável fornecido.")
            
    # 2. Validação do Frontend (Pattern Matching) - Alterado o filtro e adicionada a limpeza de Markdown
    if codigo_frontend and len(codigo_frontend.strip()) > 10: 
        try:
            # NOVA LINHA: Limpeza estrutural para garantir o Pattern Matching
            codigo_limpo_front = codigo_frontend.replace("```jsx", "").replace("```javascript", "").replace("```html", "").replace("```react", "").replace("```", "")
            scanner_front = FrontendSecurityScanner()
            scanner_front.scan_code(codigo_limpo_front)
            
            if scanner_front.vulnerabilidades:
                relatorio.append("🎨 FRONTEND (Pattern-Matching):\n" + "\n".join(scanner_front.vulnerabilidades))
            else:
                relatorio.append("✅ FRONTEND (Pattern-Matching): Nenhuma inconformidade determinística detectada.")
        except Exception as e:
            relatorio.append(f"❌ FRONTEND Falha interna do Scanner Regex: {str(e)}")
    else:
        relatorio.append("⚠️ FRONTEND: Nenhum código processável fornecido.")

    if not relatorio:
         return "Nenhum código para análise."
    return "\n\n".join(relatorio)

# ==========================================
# 4. OS DEPARTAMENTOS (NÓS DA FÁBRICA)
# ==========================================
def departamento_arquiteto(estado: Prancheta):
    print("👷 [Arquiteto] Planejando a solução...")
    try:
        rag = GraphRAGBuilder() # Inicialização segura
        contexto = rag.construir_contexto_hibrido(estado['estoria_usuario'])
    except Exception as e:
        print(f"⚠️ Aviso: Falha ao carregar GraphRAG: {e}")
        contexto = "Contexto RAG indisponível."
        
    prompt = f"Você é um Arquiteto de Software. Crie um plano técnico conciso para as frentes Frontend e Backend para a demanda: {estado['estoria_usuario']}\nContexto:\n{contexto}"
    resposta = get_llm().invoke(prompt)
    return {"plano_tecnico": resposta.content}

def departamento_backend(estado: Prancheta):
    prompt = f"""Você é um Desenvolvedor Backend Sênior Python/FastAPI. 
    Plano: {estado['plano_tecnico']}
    Correções: {estado.get('comentarios_revisor', 'Nenhum.')}
    Escreva APENAS o código."""
    resposta = get_llm().invoke(prompt)
    return {"codigo_backend": resposta.content}

def departamento_frontend(estado: Prancheta):
    # Alteração: Instrução defensiva para evitar o uso de localStorage
    prompt = f"""Você é um Dev Frontend Sênior React. 
    Plano: {estado['plano_tecnico']}
    Backend: {estado['codigo_backend']}
    Correções: {estado.get('comentarios_revisor', 'Nenhum.')}
    Atenção: NÃO use localStorage ou sessionStorage para armazenar tokens JWT, pois isso viola as políticas de segurança. Opte por variáveis de estado em memória (React State) ou instrua o uso de cookies HTTP-Only no backend.
    Escreva APENAS o código interativo."""
    resposta = get_llm().invoke(prompt)
    return {"codigo_frontend": resposta.content}

def departamento_qa(estado: Prancheta):
    prompt = f"Escreva testes unitários em pytest para o seguinte backend:\n{estado['codigo_backend']}"
    resposta = get_llm().invoke(prompt)
    return {"testes_gerados": resposta.content}

def departamento_revisor(estado: Prancheta):
    print("🕵️ [Revisor AppSec] Auditoria de Segurança, Qualidade e Integração...")
    analise_hibrida = executar_analise_estatica_hibrida(estado['codigo_backend'], estado['codigo_frontend'])
    
    prompt = f"""Você é um Tech Lead AppSec.
    Audite rigorosamente:
    Backend: {estado['codigo_backend']}
    Frontend: {estado['codigo_frontend']}
    Scanner SAST: {analise_hibrida}

    REGRA DE ZERO-TRUST:
    Você DEVE explicar as falhas detalhadamente e ordenar que os desenvolvedores corrijam a vulnerabilidade.
    Só responda a palavra 'APROVADO' de forma isolada se o código estiver 100% seguro e o Scanner disser 'Perfeito' para ambos.
    """
    resposta = get_llm().invoke(prompt).content

    # HARD-STOP: A aprovação depende de duas condições inegociáveis:
    # 1. O LLM dizer "APROVADO" explicitamente.
    # 2. O Scanner não conter símbolos de erro (🛑, ❌) nem avisos (⚠️).
    possui_erros_sast = any(simbolo in analise_hibrida for simbolo in ["🛑", "⚠️", "❌"])

    if "APROVADO" in resposta.upper() and not possui_erros_sast:
        return {"aprovado": True, "comentarios_revisor": "Aprovado sem ressalvas.", "analise_estatica_ast": analise_hibrida}
    
    # Se o LLM disse APROVADO, mas o SAST encontrou erro, nós forçamos a reprovação.
    if possui_erros_sast and "APROVADO" in resposta.upper():
        resposta = f"REPROVADO PELO SISTEMA: O Tech Lead IA tentou aprovar, mas o SAST Scanner detectou anomalias inegociáveis:\n{analise_hibrida}\n\nComentários do Tech Lead: {resposta}"

    return {"aprovado": False, "comentarios_revisor": resposta, "analise_estatica_ast": analise_hibrida}

def decidir_proximo_passo(estado: Prancheta):
    return "Finalizar" if estado.get("aprovado") else "Refazer"

fluxograma = StateGraph(Prancheta)
fluxograma.add_node("Arquiteto", departamento_arquiteto)
fluxograma.add_node("Backend", departamento_backend)
fluxograma.add_node("Frontend", departamento_frontend)
fluxograma.add_node("QA", departamento_qa)
fluxograma.add_node("Revisor", departamento_revisor)

fluxograma.set_entry_point("Arquiteto")
fluxograma.add_edge("Arquiteto", "Backend")
fluxograma.add_edge("Backend", "Frontend")
fluxograma.add_edge("Frontend", "QA")
fluxograma.add_edge("QA", "Revisor")
fluxograma.add_conditional_edges("Revisor", decidir_proximo_passo, {"Refazer": "Backend", "Finalizar": END})
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
    return {"status": "ok", "servico": "Gerente Orquestrador IA v4.3 (Zero-Trust)"}

@app.post("/executar")
def executar_fluxo(requisicao: TarefaRequest):
    try:
        resultado = gerente_oficial.invoke({"estoria_usuario": requisicao.estoria_usuario, "aprovado": False}, {"recursion_limit": 10})
        return {
            "plano_tecnico": resultado.get("plano_tecnico"),
            "codigo_backend": resultado.get("codigo_backend"),
            "codigo_frontend": resultado.get("codigo_frontend"),
            "testes_gerados": resultado.get("testes_gerados"),
            "analise_ast": resultado.get("analise_estatica_ast"),
            "aprovado": resultado.get("aprovado"),
            "relatorio_final_revisor": resultado.get("comentarios_revisor") # Alteração: Expõe o comentário
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/revisar_pr")
def revisar_pr_direto(requisicao: TarefaRequest):
    """
    Auditoria direta de Pull Requests no GitHub (DevSecOps)
    """
    token = os.environ.get("GITHUB_TOKEN")
    if not token or not requisicao.numero_pr:
        raise HTTPException(status_code=400, detail="Token do GitHub ou número do PR ausentes na requisição ou ambiente.")
    
    try:
        # 1. Busca o Diff (Código Alterado) do GitHub
        url_diff = f"https://api.github.com/repos/{requisicao.repositorio}/pulls/{requisicao.numero_pr}"
        cabecalhos_diff = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3.diff"}
        resposta_diff = requests.get(url_diff, headers=cabecalhos_diff)
        
        if resposta_diff.status_code != 200:
             raise HTTPException(status_code=404, detail="PR não encontrado ou sem acesso.")
             
        codigo_alterado = resposta_diff.text

        # 2. Separa apenas as linhas em Python para alimentar o Scanner AST sem quebrar
        linhas_python = [line for line in codigo_alterado.split('\n') if not line.startswith('-') and (line.endswith('.py') or any(k in line for k in ['def ', 'import ', 'class ']))]
        codigo_python_sozinho = "\n".join(linhas_python)

        # 3. Executa o Scanner SAST Determinístico
        analise_hibrida = executar_analise_estatica_hibrida(codigo_python_sozinho, codigo_alterado)

        # 4. Avaliação LLM (Tech Lead)
        prompt_revisor_avancado = f"""Você é um Inspetor AppSec.
        Analise o diff do PR. Scanner SAST: {analise_hibrida}
        
        REGRA ZERO-TRUST:
        Se houver QUALQUER erro grave (🛑), aviso inseguro (⚠️) ou erro de sintaxe/falha (❌), reprove e explique a correção.
        Só responda 'APROVADO' de forma isolada se o código estiver perfeitamente blindado."""
        
        parecer = get_llm().invoke(prompt_revisor_avancado).content

        # 5. HARD-STOP: A palavra final é do Python, não da IA
        possui_erros_sast = any(simbolo in analise_hibrida for simbolo in ["🛑", "⚠️", "❌"])
        aprovado = "APROVADO" in parecer.upper() and not possui_erros_sast

        # Proteção contra Alucinação: Se a IA aprovou algo com erro, sobrescreve o texto dela
        if possui_erros_sast and "APROVADO" in parecer.upper():
            parecer = f"**REPROVADO PELO SISTEMA (HARD-STOP):** O Tech Lead IA tentou aprovar o PR, mas o SAST Scanner detectou anomalias inegociáveis.\n\n**Comentário original da IA:**\n{parecer}"

        # 6. Geração de Testes (QA)
        prompt_qa = f"Crie testes unitários automáticos usando pytest para o código modificado na PR:\n{codigo_alterado}"
        testes_sugeridos = get_llm().invoke(prompt_qa).content

        # 7. Posta o comentário de volta no PR no GitHub
        url_comentario = f"https://api.github.com/repos/{requisicao.repositorio}/issues/{requisicao.numero_pr}/comments"
        cabecalhos_comentario = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"}
        icone = "✅ APROVADO" if aprovado else "❌ REPROVADO PELO APPSEC"

        comentario_final = (
            f"### 🕵️ Auditoria AppSec (Zero-Trust)\n**Status:** {icone}\n\n"
            f"**Análise Estática (SAST):**\n{analise_hibrida}\n\n"
            f"**Parecer Técnico (IA):**\n{parecer}\n\n"
            f"---\n### 🧪 Sugestão de Testes Automáticos (QA)\n{testes_sugeridos}"
        )

        resp = requests.post(url_comentario, json={"body": comentario_final}, headers=cabecalhos_comentario)
        
        return {"status": "revisado", "github_status": resp.status_code, "aprovado": aprovado}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# @app.post("/revisar_pr")
# def revisar_pr_direto(requisicao: TarefaRequest):
#     """
#     Auditoria direta de Pull Requests no GitHub
#     """
#     token = os.environ.get("GITHUB_TOKEN")
#     if not token or not requisicao.numero_pr:
#         raise HTTPException(status_code=400, detail="Token do GitHub ou número do PR ausentes.")
    
#     try:
#         url_diff = f"https://api.github.com/repos/{requisicao.repositorio}/pulls/{requisicao.numero_pr}"
#         cabecalhos_diff = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3.diff"}
#         resposta_diff = requests.get(url_diff, headers=cabecalhos_diff)
        
#         if resposta_diff.status_code != 200:
#              raise HTTPException(status_code=404, detail="PR não encontrado ou sem acesso.")
             
#         codigo_alterado = resposta_diff.text

#         linhas_python = [line for line in codigo_alterado.split('\n') if not line.startswith('-') and (line.endswith('.py') or any(k in line for k in ['def ', 'import ', 'class ']))]
#         codigo_python_sozinho = "\n".join(linhas_python)

#         analise_hibrida = executar_analise_estatica_hibrida(codigo_python_sozinho, codigo_alterado)

#         prompt_revisor_avancado = f"""Você é um Inspetor de Segurança Sênior (AppSec).
#         Analise o 'git diff' recebido.

#         Diff:
#         {codigo_alterado}

#         SAST Scanner:
#         {analise_hibrida}

#         REGRA ZERO-TRUST:
#         Reprove sumariamente se o SAST Scanner apontar qualquer vulnerabilidade grave (🛑) ou aviso de design inseguro (⚠️).
#         Responda 'APROVADO' apenas se o código estiver perfeitamente blindado. Senão, explique as correções."""

#         parecer = get_llm().invoke(prompt_revisor_avancado).content
#         aprovado = "APROVADO" in parecer.upper() and "🛑" not in analise_hibrida and "⚠️" not in analise_hibrida

#         prompt_qa = f"Crie testes pytest para o diff: {codigo_alterado}"
#         testes_sugeridos = get_llm().invoke(prompt_qa).content

#         url_comentario = f"https://api.github.com/repos/{requisicao.repositorio}/issues/{requisicao.numero_pr}/comments"
#         cabecalhos_comentario = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"}
#         icone = "✅ APROVADO" if aprovado else "❌ REPROVADO PELO APPSEC"

#         comentario_final = (
#             f"### 🕵️ Auditoria AppSec (Zero-Trust)\n**Status:** {icone}\n\n"
#             f"**Análise Estática (SAST):\n{analise_hibrida}\n\n"
#             f"**Parecer Técnico (IA):\n{parecer}\n\n"
#             f"---\n### 🧪 Sugestão de Testes Automáticos\n{testes_sugeridos}"
#         )

#         resp = requests.post(url_comentario, json={"body": comentario_final}, headers=cabecalhos_comentario)
        
#         return {"status": "revisado", "github_status": resp.status_code, "aprovado": aprovado}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
