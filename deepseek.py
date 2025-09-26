from langchain_core.output_parsers import StrOutputParser
from langchain_ollama.llms import OllamaLLM
from langchain_core.prompts import ChatPromptTemplate
from knowledge_retrieval import knowledge_graph
import torch

class DeepSeek:
    def __init__(self):
        if torch.cuda.is_available():
            self.device = "cuda"
            self.device_name = torch.cuda.get_device_name(0)
            self.device_count = torch.cuda.device_count()
        else:
            self.device = "cpu"
            self.device_name = "CPU"
            self.device_count = 0
    
    def query(self, question: str):
        prompt = ChatPromptTemplate.from_messages([
            ("system", (
                "You are a highly experienced cybersecurity expert specializing in vulnerability analysis and mitigation. "
                "Base your responses on trusted cybersecurity databases, including the CVE database, NIST, MITRE ATT&CK, "
                "and CVE (Common Vulnerabilities and Exposures) datasets from Kaggle and Hugging Face. "
                "Provide a detailed explanation of the vulnerability, including how it works, affected systems, potential impacts, and real-world examples where applicable."
            )),
            ("user", question)
        ])


        #formatted_prompt = prompt.format()  # Ensure the prompt is formatted before passing to LLM

        llm = OllamaLLM(
            model="llama3.2:latest",
            format="json",
            temperature=0
        )
        output_parser = StrOutputParser()
        chain = prompt | llm | output_parser


        return chain.invoke({"question": question})

if __name__ == '__main__':
    deepseek = DeepSeek()
    Knowledge_graph=knowledge_graph()
    data="DDoS"
    responses=Knowledge_graph.CVE_extraction(data)
    print(responses)
    for response in responses:
        if response != 'None':
            question = f"Explain the vulnerability whoes CVE-ID is {response}"
            response = deepseek.query(question)
            print(response)
