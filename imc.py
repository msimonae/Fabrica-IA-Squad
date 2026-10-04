def calcular_imc_e_status(peso_kg: float, altura_m: float) -> tuple[float, str\]:
    """
    Calcula o Índice de Massa Corporal (IMC) e classifica o resultado em categorias padrão.

    Args:
        peso_kg (float): O peso da pessoa em quilogramas.
        altura_m (float): A altura da pessoa em metros.

    Returns:
        tuple[float, str\]: Uma tupla contendo o valor do IMC
        (arredondado para 2 casas decimais) e a categoria correspondente.

    Raises:
        ValueError: Se o peso ou a altura forem valores não positivos.
    """

    # 1. Validação de Entradas
    if peso_kg <= 0:
        raise ValueError("O peso deve ser um valor positivo.")

    if altura_m <= 0:
        raise ValueError(
            "A altura deve ser um valor positivo e diferente de zero."
        )

    # 2. Cálculo do IMC
    imc = peso_kg / (altura_m ** 2)

    # 3. Classificação do IMC
    if imc < 18.5:
        status_imc = "Abaixo do Peso"
    elif 18.5 <= imc < 25.0:
        status_imc = "Peso Normal"
    elif 25.0 <= imc < 30.0:
        status_imc = "Sobrepeso"
    elif 30.0 <= imc < 35.0:
        status_imc = "