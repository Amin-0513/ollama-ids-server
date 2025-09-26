from langchain_core.output_parsers import StrOutputParser
from langchain_ollama.llms import OllamaLLM
from langchain_core.prompts import ChatPromptTemplate
import torch

class DeepSeekD:
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
            ("system", 
                "You are a cybersecurity expert specializing in vulnerability analysis. "
                "Use trusted sources such as CVE, MITRE ATT&CK, and NIST to analyze the given vulnerability. "
                "Provide a concise summary with the CVE ID, affected systems, impact, and a brief technical description."
            ),
            ("user", "Analyze the following JSON and summarize the vulnerability:\n\n{message}")
        ])

        llm = OllamaLLM(
            model="llama3.2:latest",
            format="",
            temperature=0
        )
        output_parser = StrOutputParser()
        chain = prompt | llm | output_parser

        return chain.invoke({"message": question})

if __name__ == '__main__':
    deepseek = DeepSeekD()
    text = '''
    {
        "message": [
            "{ \"CVE\": \"CVE-1999-0116\", \"Vulnerability Name\": \"Buffer Overflow in the 'gethostbyname' Function\" }",
            "{\n  \"CVE\": {\n    \"ID\": \"CVE-1999-0016\",\n    \"Title\": \"Buffer overflow in the 'gethostbyname' function of the Berkeley sockets library\",\n    \"Description\": \"A buffer overflow vulnerability was discovered in the 'gethostbyname' function of the Berkeley sockets library. This function is used to resolve hostnames to IP addresses. The vulnerability allows an attacker to execute arbitrary code on a system by crafting a specially crafted DNS query.\",\n    \"Impact\": \"This vulnerability could allow an attacker to execute arbitrary code on a system, potentially leading to unauthorized access or data theft.\"\n  }\n}",
            "{ \"CVE\": \"CVE-1999-0513\", \"Vulnerability Name\": \"Buffer Overflow in the 'gethostbyname' Function\" }",
            "{\n  \"CVE\": {\n    \"ID\": \"CVE-1999-0153\",\n    \"Title\": \"Buffer overflow in the 'gethostbyname' function of the Berkeley sockets library\",\n    \"Description\": \"A buffer overflow vulnerability exists in the 'gethostbyname' function of the Berkeley sockets library. This allows an attacker to execute arbitrary code on a system running the vulnerable version of the library.\"\n  }\n}",
            "{\n  \"vulnerability\": \"CVE-1999-0660\",\n  \"description\": \"The vulnerability is a buffer overflow in the 'strcpy' function of the 'winsock2.dll' library, which is used for network communication. The vulnerability allows an attacker to execute arbitrary code on the system by sending a specially crafted packet to the affected application.\",\n  \"affected_systems\": [\n    \"Windows NT 4.0\",\n    \"Windows 2000\"\n  ],\n  \"potential_impacts\": [\n    \"Arbitrary code execution\",\n    \"Denial of Service (DoS)\"\n  ],\n  \"real_world_examples\": [\n    \"In 1999, a vulnerability was discovered in the 'winsock2.dll' library that allowed an attacker to execute arbitrary code on a system running Windows NT 4.0 or Windows 2000. The vulnerability was exploited by hackers to spread malware and gain unauthorized access to systems.\"\n  ]\n}"
        ]
    }
    '''
    question = f"Summarize the JSON: {text}"
    response = deepseek.query(question)
    print(response)