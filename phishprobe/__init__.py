"""PhishProbe — adversarial testing of a phishing email classifier.

Public surface:
    get_classifier()   -> pick a backend (heuristic offline, or an LLM)
    Classification     -> a single classify() result
    extract_iocs()     -> pull structured IOCs out of an email
    DecisionBoundaryProber -> probe a classifier with adversarial perturbations
"""

from .classifier import Classification, BaseClassifier, HeuristicClassifier, LLMClassifier, get_classifier
from .iocs import extract_iocs, Indicator
from .prober import DecisionBoundaryProber, ProbeResult

__all__ = [
    "Classification",
    "BaseClassifier",
    "HeuristicClassifier",
    "LLMClassifier",
    "get_classifier",
    "extract_iocs",
    "Indicator",
    "DecisionBoundaryProber",
    "ProbeResult",
]

__version__ = "1.0.0"
