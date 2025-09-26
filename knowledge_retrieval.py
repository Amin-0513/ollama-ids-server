from langchain_community.graphs import Neo4jGraph
class knowledge_graph:
    def __init__(self):
        self.NEO4j_URL="neo4j+s://affc2236.databases.neo4j.io"
        self.NEO4j_USERNAME="neo4j"
        self.NEO4j_PASSWORD="nCzi2z_tel-kiYqLrNS2tis7fc0ed5A_6L9ov0c3Y5U"
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


