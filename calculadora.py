def calcular_matematica(expressao_usuario):
    # O uso de eval() sem sanitização é uma vulnerabilidade (Code Injection)
    resultado = eval(expressao_usuario)
    print(f"O resultado é: {resultado}")
    return resultado
