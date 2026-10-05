import re
# import numexpr # Descomente se for usar numexpr

def calcular_matematica_seguro(expressao_usuario):
    # 1. Validação rigorosa da entrada (primeira linha de defesa)
    # Permite apenas números, operadores básicos (+, -, *, /), parênteses e espaços.
    # Esta regex é um bom começo, mas um parser robusto é a melhor solução.
    if not re.fullmatch(r"[\d\s\+\-\*/\(\)\.]+", expressao_usuario):
        raise ValueError("Expressão inválida: contém caracteres não permitidos ou formato incorreto.")

    # 2. Substituir eval() por um mecanismo de avaliação seguro.
    # A melhor abordagem é usar uma biblioteca de parsing de expressões matemáticas segura.
    try:
        # Exemplo com numexpr:
        # resultado = numexpr.evaluate(expressao_usuario).item()
        # print(f"O resultado é: {resultado}")
        # return resultado

        # Se não puder usar bibliotecas externas, um parser customizado robusto seria necessário.
        # Isso é significativamente mais complexo do que o escopo deste exemplo e deve ser
        # implementado por especialistas em segurança e parsing.

        # Para fins de demonstração e para remover o eval inseguro,
        # vamos levantar um erro indicando que um mecanismo seguro precisa ser implementado.
        raise NotImplementedError(
            "A avaliação segura de expressões matemáticas requer um parser robusto "
            "ou uma biblioteca dedicada (ex: numexpr, sympy, asteval). "
            "O uso de eval() foi removido por ser inseguro."
        )

    except Exception as e:
        # Captura erros de parsing ou avaliação da biblioteca/parser seguro
        raise ValueError(f"Erro ao avaliar a expressão matemática: {e}")

# Exemplo de uso (após implementar o mecanismo seguro):
# print(calcular_matematica_seguro("10 + 5 * (2 - 1)"))
# print(calcular_matematica_seguro("2**3")) # Se o parser suportar **
# print(calcular_matematica_seguro("__import__('os').system('ls')")) # Isso deve falhar na validação ou no parser
