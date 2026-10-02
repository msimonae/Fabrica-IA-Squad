from langgraph.graph import StateGraph

# 1. O Gerente define o que é a "Prancheta de Trabalho" (Estado)
# A prancheta vai guardar o código, os erros e a aprovação.

# 2. O Gerente cria os departamentos (Nós/Nodes)
def departamento_arquiteto(prancheta):
    # Lê a estória e planeja
    return plano

def departamento_programador(prancheta):
    # Escreve o código
    return codigo

def departamento_revisor(prancheta):
    # Avalia a segurança
    return relatorio_de_erros

# 3. O Gerente desenha o Fluxograma (Grafo)
fluxograma = StateGraph(Prancheta)

fluxograma.add_node("Arquiteto", departamento_arquiteto)
fluxograma.add_node("Programador", departamento_programador)
fluxograma.add_node("Revisor", departamento_revisor)

# 4. O Gerente define a ordem das mesas (Arestas/Edges)
fluxograma.add_edge("Arquiteto", "Programador")
fluxograma.add_edge("Programador", "Revisor")

# 5. A regra condicional: Se o Revisor achar erro, devolve pro Programador. Se não, finaliza.
# (Isso cria o loop de correção automática)