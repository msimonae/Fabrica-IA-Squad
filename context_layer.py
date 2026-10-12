import os
import logging
from jira import JIRA
from github import Github
from neo4j import GraphDatabase
from pymilvus import MilvusClient
from langchain_google_vertexai import VertexAIEmbeddings

# Configuração de log para não "engolir" os erros no Cloud Run
logger = logging.getLogger(__name__)

class GraphRAGBuilder:
    def __init__(self):
        # 1. Validação de segurança (Fail-Closed)
        self._validar_credenciais_obrigatorias([
            "GITHUB_TOKEN", "JIRA_SERVER_URL", "JIRA_EMAIL", 
            "JIRA_API_TOKEN", "NEO4J_PASSWORD", "MILVUS_TOKEN"
        ])
        
        # 2. Inicialização Protegida
        try:
            self.github_client = Github(os.environ.get("GITHUB_TOKEN"))
            
            self.jira_client = JIRA(
                server=os.environ.get("JIRA_SERVER_URL"),
                basic_auth=(os.environ.get("JIRA_EMAIL"), os.environ.get("JIRA_API_TOKEN"))
            )
            
            self.neo4j_driver = GraphDatabase.driver(
                os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                auth=(os.environ.get("NEO4J_USER", "neo4j"), os.environ.get("NEO4J_PASSWORD", "password"))
            )
            
            self.milvus_client = MilvusClient(
                uri=os.environ.get("MILVUS_URI", "http://localhost:19530"),
                token=os.environ.get("MILVUS_TOKEN", "")
            )
            
            self.embeddings_model = VertexAIEmbeddings(model_name="textembedding-gecko@003")
            
        except Exception as e:
            # Em vez de quebrar silenciosamente, registra o erro no Cloud Logging e lança
            logger.error(f"Falha ao iniciar os clientes do GraphRAG: {str(e)}")
            raise RuntimeError(f"Erro na inicialização da infraestrutura RAG: {str(e)}")

    def _validar_credenciais_obrigatorias(self, chaves: list):
        """Impede a execução se o Secret Manager falhou em injetar as chaves."""
        ausentes = [chave for chave in chaves if not os.environ.get(chave)]
        if ausentes:
            msg = f"Vazamento ou falha de infra: Credenciais não encontradas: {', '.join(ausentes)}"
            logger.critical(msg)
            raise ValueError(msg)

    def extrair_estoria_jira(self, issue_key: str) -> str:
        """Busca a descrição original, regras de negócio e critérios de aceite do Jira."""
        try:
            issue = self.jira_client.issue(issue_key)
            descricao = issue.fields.description if issue.fields.description else "Sem descrição no Jira."
            return f"Título: {issue.fields.summary}\nDescrição: {descricao}"
        except Exception as e:
            logger.warning(f"Aviso: Não foi possível acessar o Jira para a issue {issue_key}: {e}")
            return "Erro ao acessar detalhes do Jira."

    def buscar_contexto_vetorial_milvus(self, query: str, limit: int = 3) -> str:
        """Busca os trechos de código mais semanticamente parecidos com a demanda na codebase."""
        try:
            query_embedding = self.embeddings_model.embed_query(query)
            resultados = self.milvus_client.search(
                collection_name="codebase_embeddings",
                data=[query_embedding],
                limit=limit,
                output_fields=["filepath", "code_snippet"]
            )
            
            if not resultados or not resultados[0]:
                return "Nenhum código semelhante encontrado."
                
            contexto = "Arquivos Semelhantes na Base (Milvus):\n"
            for hit in resultados[0]:
                contexto += f"- {hit['entity'].get('filepath')}:\n{hit['entity'].get('code_snippet')}\n"
            return contexto
        except Exception as e:
            logger.warning(f"Falha na busca vetorial: {e}")
            return "Erro ao consultar base vetorial."

    def buscar_dependencias_grafo_neo4j(self, keywords: list) -> str:
        """Busca relações estruturais: quem chama o quê (Imports, Heranças)."""
        query = """
        MATCH (f:Function)-[:CALLS]->(dep:Function)
        WHERE f.name IN $keywords OR dep.name IN $keywords
        RETURN f.name AS origem, dep.name AS destino, f.filepath AS arquivo
        LIMIT 10
        """
        try:
            with self.neo4j_driver.session() as session:
                result = list(session.run(query, keywords=keywords))
                if not result:
                    return "Nenhuma dependência estrutural encontrada."
                    
                contexto = "Dependências Estruturais da Codebase (Neo4j):\n"
                for record in result:
                    contexto += f"- A função '{record['origem']}' (em {record['arquivo']}) chama '{record['destino']}'.\n"
                return contexto
        except Exception as e:
            logger.warning(f"Falha na busca de grafos: {e}")
            return "Erro ao consultar banco de grafos."

    def construir_contexto_hibrido(self, estoria_usuario: str, issue_jira: str = None) -> str:
        """Orquestra a extração do RAG Híbrido para enviar ao Agente Arquiteto."""
        contexto_final = ""
        
        if issue_jira:
            contexto_final += "=== REQUISITOS DO PRODUTO (JIRA) ===\n"
            contexto_final += self.extrair_estoria_jira(issue_jira) + "\n\n"
            
        contexto_final += "=== CONTEXTO SEMÂNTICO (MILVUS) ===\n"
        contexto_final += self.buscar_contexto_vetorial_milvus(estoria_usuario) + "\n\n"
        
        # Limpeza básica das keywords
        palavras_limpas = [p.strip(".,;:?!\"'") for p in estoria_usuario.split()]
        keywords = palavras_limpas[:5] 
        
        contexto_final += "=== IMPACTO ARQUITETURAL (NEO4J) ===\n"
        contexto_final += self.buscar_dependencias_grafo_neo4j(keywords)
        
        return contexto_final
