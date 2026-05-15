from abc import ABC, abstractmethod

class BaseDetector(ABC):
    @abstractmethod
    def analyze(self, packets) -> list[dict]:
        """
        Takes a list of scapy packets
        Returns list of finding dicts, each with 
        - serverity: "High / "Medium" / "Low"
        - description: short label 
        - detail: longer explanation 
        - src: source IP 
        """
        pass 


    