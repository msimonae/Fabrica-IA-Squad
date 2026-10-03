from langchain_google_vertexai import ChatVertexAI
from langgraph.graph import StateGraph
from typing import TypedDict

# 1. Definir a prancheta de trabalho (Estado do LangGraph)
class Prancheta(TypedDict):
    estoria_usuario: str
    plano_tecnico: str

# 2. Conectar ao Gemini 2.5 Flash (Custo Zero de Hospedagem)
# O Google Cloud Run já sabe automaticamente em qual projeto está devido ao passo 2, 
# então você só precisa informar o nome do modelo.
llm_gemini = ChatVertexAI(
    model_name="gemini-2.5-flash",
    temperature=0.1 # Temperatura baixa (0.1) deixa a IA focada na lógica e precisão para código
)

# 3. Criar o departamento do Arquiteto (Nó)
def departamento_arquiteto(estado: Prancheta):
    estoria = estado["estoria_usuario"]
    
    # A instrução que o Agente vai receber
    prompt = f"Você é um Arquiteto de Software Sênior. Escreva um plano técnico para a estória: {estoria}"
    
    # O Gemini analisa o prompt, processa o raciocínio lógico e devolve a resposta
    resposta = llm_gemini.invoke(prompt)
    
    # Anota o resultado de volta na prancheta
    return {"plano_tecnico": resposta.content}

# 4. Montar o fluxo do LangGraph
fluxograma = StateGraph(Prancheta)

# Adiciona a "mesa" de trabalho do Arquiteto
fluxograma.add_node("Arquiteto", departamento_arquiteto)

# Define onde o processo começa e termina
fluxograma.set_entry_point("Arquiteto")
fluxograma.set_finish_point("Arquiteto")

# Compila o gerente para ele ficar pronto para rodar e receber as requisições do webhook
gerente_oficial = fluxograma.compile()
