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

app = FastAPI(title="Gerente Orquestrador IA - V4.2 (Dual-Stack Dev: QA + Advanced Hybrid AppSec)")

# ==========================================
# 1. A PRANCHETA DE TRABALHO (ESTADO)
# ==========================================
class Prancheta(TypedDict):
    estoria_usuario: str
    plano_tecnico: str
    codigo_backend: str       # Isolado: Código de servidor / API
    codigo_frontend: str      # Isolado: Interface de Usuário (React, HTML/JS)
    testes_gerados: str       # Cobertura QA
    comentarios_revisor: str
    aprovado: bool
    analise_estatica_ast: str  # Relatório completo do Scanner Híbrido (XAI)

# =========================================================================
# 2. O MÓDULO XAI DE ANÁLISE ESTÁTICA AVANÇADA (SAST POLIGLOTA: AST + PATTERNS)
# =========================================================================

# --- 2.1 SCANNER DE BACKEND (PYTHON AST) ---
class ASTSecurityScanner(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilidades: List[str] = []

    def visit_Call(self, node: ast.Call):
        # Injeção de Código (eval, exec, input)
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in ['eval', 'exec', 'input']:
                self.vulnerabilidades.append(
                    f"🛑 [A03:2021-Injection (Backend)] Chamada perigosa '{func_name}()' na Linha {node.lineno}. "
                    "Risco: Execução de código arbitrário e não confiável."
                )
            
            # Injeção de Comando de Sistema (os.system, os.popen)
            if func_name in ['system', 'popen'] or (isinstance(node.func, ast.Attribute) and node.func.attr in ['system', 'popen']):
                self.vulnerabilidades.append(
                    f"🛑 [A03:2021-Injection (Backend)] Chamada 'os.{func_name if isinstance(node.func, ast.Name) else node.func.attr}()' na Linha {node.lineno}. "
                    "Risco: Execução de comandos do sistema operacional (Command Injection)."
                )

        # Injeção de Comando via Subprocess (shell=True)
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in ['Popen', 'run', 'call', 'check_output']:
                for keyword in node.keywords:
                    if keyword.arg == 'shell':
                        if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                            self.vulnerabilidades.append(
                                f"🛑 [A03:2021-Injection (Backend)] Uso de 'subprocess.{node.func.attr}(shell=True)' na Linha {node.lineno}. "
                                "Risco: Criação de subprocesso vulnerável a Shell Injection."
                            )

            # Desserialização Insegura (pickle, marshal, yaml)
            if isinstance(node.func.value, ast.Name) and node.func.value.id in ['pickle', 'marshal', 'yaml', 'shelve']:
                if node.func.attr in ['loads', 'load', 'unsafe_load']:
                    if not (node.func.value.id == 'yaml' and node.func.attr == 'safe_load'):
                        self.vulnerabilidades.append(
                            f"🛑 [A08:2021-Integridade (Backend)] Desserialização insegura '{node.func.value.id}.{node.func.attr}()' na Linha {node.lineno}. "
                            "Risco: Deserialização de dados não confiáveis pode levar à execução de código remoto (RCE)."
                        )

            # Criptografia / Hashes Fracos
            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'hashlib':
                if node.func.attr in ['md5', 'sha1']:
                    self.vulnerabilidades.append(
                        f"⚠️ [A02:2021-Criptografia (Backend)] Algoritmo de hash fraco 'hashlib.{node.func.attr}()' na Linha {node.lineno}. "
                        "Risco: Algoritmo suscetível a colisões. Use SHA-256 ou superior."
                    )

            # Risco de SQL Injection
            if node.func.attr in ['execute', 'executemany']:
                if node.args:
                    primeiro_arg = node.args[0]
                    if (isinstance(primeiro_arg, ast.JoinedStr) or 
                        (isinstance(primeiro_arg, ast.BinOp) and isinstance(primeiro_arg.op, ast.Mod)) or
                        (isinstance(primeiro_arg, ast.Call) and isinstance(primeiro_arg.func, ast.Attribute) and primeiro_arg.func.attr == 'format')):
                        self.vulnerabilidades.append(
                            f"🛑 [A03:2021-Injection (Backend)] Potencial SQL Injection na Linha {node.lineno} (chamada '.{node.func.attr}()'). "
                            "Risco: Consulta SQL construída dinamicamente com interpolação de strings. Utilize consultas parametrizadas."
                        )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Vazamento de Dados Sensíveis (Credenciais/Tokens)
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.upper()
                if any(k in var_name for k in ["PASSWORD", "SENHA", "SECRET", "CREDENTIAL", "TOKEN", "API_KEY", "JWT"]):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if len(node.value.value) > 4 and not any(p in node.value.value.upper() for p in ["YOUR", "ENV", "PLACEHOLDER", "INSERT"]):
                            self.vulnerabilidades.append(
                                f"🛑 [A02:2021-Criptografia (Backend)] Vazamento de Dados Sensíveis na Linha {node.lineno}. "
                                f"A variável '{target.id}' aparenta conter um valor confidencial estático (hardcoded)."
                            )
        self.generic_visit(node)


# --- 2.2 SCANNER DE FRONTEND (REGEX & PATTERN MATCHING) ---
class FrontendSecurityScanner:
    def __init__(self):
        self.vulnerabilidades: List[str] = []

    def scan_code(self, code: str):
        if not code:
            return
        
        # 1. Risco de Client-Side XSS (innerHTML ou dangerouslySetInnerHTML)
        if re.search(r'dangerouslySetInnerHTML|\.innerHTML\s*=', code):
            self.vulnerabilidades.append(
                "🛑 [A03:2021-Injection (Frontend)] Uso de 'innerHTML' ou 'dangerouslySetInnerHTML' detectado. "
                "Risco: Vulnerabilidade a Client-Side DOM Cross-Site Scripting (XSS)."
            )

        # 2. Risco de Execução de Script no Browser (eval / setTimeout com strings)
        if re.search(r'\beval\(|setTimeout\s*\(\s*["\']', code):
            self.vulnerabilidades.append(
                "🛑 [A03:2021-Injection (Frontend)] Uso de 'eval()' ou 'setTimeout()' com avaliação de strings. "
                "Risco: Execução arbitrária de código client-side."
            )

        # 3. Armazenamento Inseguro de Dados Sensíveis (local/sessionStorage)
        if re.search(r'(localStorage|sessionStorage)\.setItem\s*\(', code):
            if any(key in code.upper() for key in ["TOKEN", "JWT", "PASSWORD", "SENHA", "CREDENTIAL", "SECRET"]):
                self.vulnerabilidades.append(
                    "⚠️ [A04:2021-Design Inseguro (Frontend)] Uso de web storage para persistência de dados confidenciais. "
                    "Risco: Armazenamento inseguro no browser exposto a roubo de sessão por XSS."
                )

        # 4. Desabilitação de Sanitizadores (Cypass Security do Angular/React)
        if "bypassSecurityTrust" in code:
            self.vulnerabilidades.append(
                "⚠️ [A03:2021-Injection (Frontend)] Uso de desabilitadores de proteção (bypassSecurityTrustHtml ou similares). "
                "Risco: Desativação intencional de blindagem XSS."
            )

        # 5. Vazamento de Segredos Estáticos em Arquivo JS/JSX/Vue
        match_secret = re.findall(r'(?:API_KEY|TOKEN|SECRET|PASSWORD|JWT|SENHA)\s*=\s*["\']([^"\'{}[\]\s]{8,})["\']', code, re.IGNORECASE)
        if match_secret:
            for segredo in match_secret:
                if not any(placeholder in segredo.upper() for placeholder in ["ENV", "PLACEHOLDER", "INSERT", "YOUR", "PROCESS", "REPLACE"]):
                    self.vulnerabilidades.append(
                        "🛑 [A02:2021-Criptografia (Frontend)] Potencial vazamento de credencial estática no código frontend. "
                        "Risco: Exposição pública de chaves e dados sigilosos que serão compilados para o cliente."
                    )


def executar_analise_estatica_hibrida(codigo_backend: str, codigo_frontend: str) -> str:
    relatorio = []
    
    # Executa scanner de Backend Python (via AST)
    if codigo_backend and "Nenhum" not in codigo_backend:
        try:
            codigo_limpo = codigo_backend.replace("```python", "").replace("```", "")
            tree = ast.parse(codigo_limpo)
            scanner_back = ASTSecurityScanner()
            scanner_back.visit(tree)
            if scanner_back.vulnerabilidades:
                relatorio.append("🔍 BACKEND (Python AST):\n" + "\n".join(scanner_back.vulnerabilidades))
            else:
                relatorio.append("✅ BACKEND (Python AST): Nenhuma inconformidade determinística detectada.")
        except SyntaxError as e:
            relatorio.append(f"❌ BACKEND (Python AST) - Erro de Sintaxe ao gerar a AST (Linha {e.lineno}): {e.msg}")
        except Exception as e:
            relatorio.append(f"❌ BACKEND (Python AST) - Falha interna: {str(e)}")
            
    # Executa scanner de Frontend JS/React/HTML (via Pattern-Matching)
    if codigo_frontend and "Nenhum" not in codigo_frontend:
        try:
            scanner_front = FrontendSecurityScanner()
            scanner_front.scan_code(codigo_frontend)
            if scanner_front.vulnerabilidades:
                relatorio.append("🎨 FRONTEND (Pattern-Matching):\n" + "\n".join(scanner_front.vulnerabilidades))
            else:
                relatorio.append("✅ FRONTEND (Pattern-Matching): Nenhuma inconformidade determinística detectada.")
        except Exception as e:
            relatorio.append(f"❌ FRONTEND (Pattern-Matching) - Falha interna: {str(e)}")

    if not relatorio:
         return "Nenhum código para análise."
    return "\n\n".join(relatorio)

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
    prompt = f"Você é um Arquiteto de Software. Crie um plano técnico conciso para as frentes Frontend e Backend para a demanda: {estado['estoria_usuario']}"
    resposta = llm_cerebro.invoke(prompt)
    return {"plano_tecnico": resposta.content}

def departamento_backend(estado: Prancheta):
    print("💻 [Backend Developer] Escrevendo o código de servidor...")
    prompt = f"""Você é um Desenvolvedor Backend Sênior especialista em Python/FastAPI. 
    Com base no plano técnico: {estado['plano_tecnico']}
    Erros para corrigir das tentativas anteriores: {estado.get('comentarios_revisor', 'Nenhum.')}
    Escreva APENAS o código Python final para as APIs, sem explicações adicionais."""
    resposta = llm_cerebro.invoke(prompt)
    return {"codigo_backend": resposta.content}

def departamento_frontend(estado: Prancheta):
    print("🎨 [Frontend Developer] Projetando a interface de usuário...")
    prompt = f"""Você é um Desenvolvedor Frontend Sênior especialista em interfaces ricas (HTML5/CSS + JS moderno ou React). 
    Com base no plano técnico: {estado['plano_tecnico']}
    E consumindo os contratos e APIs Backend já criados: {estado['codigo_backend']}
    Erros para corrigir das tentativas anteriores: {estado.get('comentarios_revisor', 'Nenhum.')}
    Escreva APENAS o código interativo, responsivo e acessível para o cliente, sem explicações adicionais."""
    resposta = llm_cerebro.invoke(prompt)
    return {"codigo_frontend": resposta.content}

def departamento_qa(estado: Prancheta):
    print("🧪 [QA Agent] Gerando cobertura e testes automatizados...")
    prompt = f"""Você é um Engenheiro de QA Sênior especialista em testes automatizados.
    Escreva testes unitários e de integração utilizando o framework 'pytest' para a seguinte lógica backend:
    {estado['codigo_backend']}

    Gere testes que cubram os caminhos felizes, casos de borda e validação de exceções.
    Retorne APENAS o código de testes Python, sem explicações adicionais."""
    resposta = llm_cerebro.invoke(prompt)
    return {"testes_gerados": resposta.content}

def departamento_revisor(estado: Prancheta):
    print("🕵️ [Revisor AppSec] Auditoria de Segurança, Qualidade e Integração...")
    
    # EXECUÇÃO DO SCANNER HÍBRIDO (BACKEND E FRONTEND)
    analise_hibrida = executar_analise_estatica_hibrida(estado['codigo_backend'], estado['codigo_frontend'])
    
    prompt = f"""Você é um Especialista de Segurança de Aplicações (AppSec) e Tech Lead. 
    Audite as implementações Frontend, Backend e os testes gerados, considerando o relatório da análise estática híbrida.

    Código Backend (Python): 
    {estado['codigo_backend']}

    Código Frontend (Interface): 
    {estado['codigo_frontend']}

    Testes Unitários Backend:
    {estado['testes_gerados']}

    Rastreabilidade e Fatos do Analisador Estático (Módulo XAI Híbrido):
    {analise_hibrida}

    Regras de Validação de AppSec e Qualidade:
    1. OWASP Top 10 (Backend): Busque por injeções (SQL, Command, eval), hashes fracos ou dados hardcoded.
    2. Vulnerabilidades Client-Side (Frontend): Inspecione o código de interface em busca de injeções de script (DOM XSS), falta de higienização de HTML, armazenamento local inseguro ou furos de integração com as rotas.
    3. Tipagem e Lógica: Ambas as camadas se integram perfeitamente?
    4. Qualidade da Cobertura: Os testes comprovam que o backend bloqueia inputs maliciosos?

    Se TUDO estiver perfeitamente seguro e bem testado, e o relatório da AST/Pattern não acusar inconformidades, responda APENAS a palavra 'APROVADO'.
    Se encontrar falhas, NÃO use a palavra APROVADO. Forneça uma explicação técnica detalhada da causa raiz do risco (seja no Front, Back ou QA), cite os nós e linhas exatas acusados na análise híbrida se aplicável e como corrigi-los para que os desenvolvedores refaçam o trabalho."""

    resposta = llm_cerebro.invoke(prompt).content

    if "APROVADO" in resposta.upper() and "🛑" not in analise_hibrida:
        print("✅ [Revisor] Solução Total Aprovada!")
        return {"aprovado": True, "comentarios_revisor": "Tudo certo.", "analise_estatica_ast": analise_hibrida}
    else:
        print(f"❌ [Revisor] Falhas encontradas: {resposta}")
        return {"aprovado": False, "comentarios_revisor": resposta, "analise_estatica_ast": analise_hibrida}

# ==========================================
# 5. A REGRA DE CONTROLE DE QUALIDADE
# ==========================================
def decidir_proximo_passo(estado: Prancheta):
    if estado.get("aprovado") is True:
        return "Finalizar"
    else:
        print("🔄 Devolvendo para os desenvolvedores refazerem código e testes...")
        return "Refazer"

# ==========================================
# 6. CONSTRUINDO O FLUXOGRAMA MULTI-AGENTE
# ==========================================
fluxograma = StateGraph(Prancheta)
fluxograma.add_node("Arquiteto", departamento_arquiteto)
fluxograma.add_node("Backend", departamento_backend)
fluxograma.add_node("Frontend", departamento_frontend)
fluxograma.add_node("QA", departamento_qa)
fluxograma.add_node("Revisor", departamento_revisor)

fluxograma.set_entry_point("Arquiteto")
fluxograma.add_edge("Arquiteto", "Backend")
fluxograma.add_edge("Backend", "Frontend")   # Frontend consome backend
fluxograma.add_edge("Frontend", "QA")       # QA testa com o ecossistema pronto
fluxograma.add_edge("QA", "Revisor")        # O revisor valida tudo junto
fluxograma.add_conditional_edges(
    "Revisor",
    decidir_proximo_passo,
    {"Refazer": "Backend", "Finalizar": END}  # Volta para correção se falhar
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
    return {"status": "ok", "servico": "Gerente Orquestrador IA v4.2 - Advanced Dual-Stack DevSecOps"}

@app.post("/executar")
def executar_fluxo(requisicao: TarefaRequest):
    try:
        configuracao = {"recursion_limit": 10}
        resultado = gerente_oficial.invoke({
            "estoria_usuario": requisicao.estoria_usuario,
            "aprovado": False
        }, configuracao)

        return {
            "plano_tecnico": resultado.get("plano_tecnico"),
            "codigo_backend": resultado.get("codigo_backend"),
            "codigo_frontend": resultado.get("codigo_frontend"),
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

        # Na análise rápida de PR, separamos o diff de Python do resto para garantir a precisão da AST
        linhas_python = [line for line in codigo_alterado.split('\n') if not line.startswith('-') and (line.endswith('.py') or any(k in line for k in ['def ', 'import ', 'class ']))]
        codigo_python_sozinho = "\n".join(linhas_python)

        # Scanner híbrido para o diff
        analise_hibrida = executar_analise_estatica_hibrida(codigo_python_sozinho, codigo_alterado)

        prompt_revisor_avancado = f"""Você é um Inspetor de Segurança Sênior (AppSec).
        Analise o 'git diff' recebido, buscando ativamente por furos no backend (OWASP Top 10) e vulnerabilidades de injeção client-side (XSS, DOM) ou dados sensíveis no frontend.

        Código Alterado no PR:
        {codigo_alterado}

        Rastreabilidade do Analisador Estático (Módulo XAI Híbrido):
        {analise_hibrida}

        Se a solução como um todo for perfeitamente segura e o relatório não acusar riscos de alta gravidade, responda 'APROVADO'. 
        Se contiver falhas (seja Python ou JS), aponte as linhas e nós e sugira a correção."""

        parecer = llm_cerebro.invoke(prompt_revisor_avancado).content
        aprovado = "APROVADO" in parecer.upper() and "🛑" not in analise_hibrida

        prompt_qa = f"""Baseado no seguinte diff de código, escreva uma suíte de testes unitários em pytest para a lógica backend alterada:
        {codigo_alterado}
        Retorne apenas o código em Python."""

        testes_sugeridos = llm_cerebro.invoke(prompt_qa).content

        url_comentario = f"https://api.github.com/repos/{requisicao.repositorio}/issues/{requisicao.numero_pr}/comments"
        cabecalhos_comentario = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"}
        icone = "✅ APROVADO" if aprovado else "❌ FALHAS DE SEGURANÇA ENCONTRADAS"

        comentario_final = (
            f"### 🕵️ Auditoria AppSec Avançada\n**Status:** {icone}\n\n"
            f"**Análise Estática de Código (SAST):\n{analise_hibrida}\n\n"
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
