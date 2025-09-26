from langchain_community.graphs import Neo4jGraph
class knowledge_graph:
    def __init__(self):
        self.NEO4j_URL=""
        self.NEO4j_USERNAME="neo4j"
        self.NEO4j_PASSWORD=""
        self.graph = Neo4jGraph(
            url= self.NEO4j_URL,
            username=self.NEO4j_USERNAME,
            password=self.NEO4j_PASSWORD
        )
    def CVE_extraction(self,data: str):
        query = f"""
        MATCH (a:AttackType {{name: '{data}'}})-[:ASSOCIATED_WITH]->(c:CVE)
        RETURN c.id AS cve_id;
        """
        res = self.graph.query(query)
        cve_ids = [record['cve_id'] for record in res]
        return cve_ids
    
if __name__ == '__main__':
    Knowledge_graph=knowledge_graph()
    data=input("Enter an attack type: ")
    response=Knowledge_graph.CVE_extraction(data)
    print(response)


