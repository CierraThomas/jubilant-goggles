 from dataclasses import dataclass, field
 from typing import List, Optional
 
 
 @dataclass(frozen=True)
 class Location:
     path: str
     line: int
     column: int
     snippet: str
 
 
 @dataclass(frozen=True)
 class Fix:
     description: str
     before: str
     after: str
     diff: str
     auto_applicable: bool = False
 
 
 @dataclass(frozen=True)
 class Finding:
     rule_id: str
     title: str
     severity: str
     confidence: str
     message: str
     location: Location
     remediation: str
     references: List[str] = field(default_factory=list)
     fix: Optional[Fix] = None
