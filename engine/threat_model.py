"""
Core data models for the Threat Modeling engine.
Defines SystemInfo, Threat, DREADScore, and ThreatModel.
"""

import uuid
from datetime import datetime


# STRIDE categories mapped to security properties
STRIDE_CATEGORIES = {
    "Spoofing": {
        "property": "Authentication",
        "description": "Impersonating a user, component, or system",
        "icon": "🎭",
        "color": "#ff4757"
    },
    "Tampering": {
        "property": "Integrity",
        "description": "Modifying data or code without authorization",
        "icon": "✏️",
        "color": "#ff6348"
    },
    "Repudiation": {
        "property": "Non-repudiation",
        "description": "Denying actions without proof of occurrence",
        "icon": "🚫",
        "color": "#ffa502"
    },
    "Information Disclosure": {
        "property": "Confidentiality",
        "description": "Exposing data to unauthorized parties",
        "icon": "👁️",
        "color": "#a55eea"
    },
    "Denial of Service": {
        "property": "Availability",
        "description": "Making systems or services unavailable",
        "icon": "⛔",
        "color": "#3742fa"
    },
    "Elevation of Privilege": {
        "property": "Authorization",
        "description": "Gaining access beyond intended permissions",
        "icon": "⬆️",
        "color": "#e84393"
    }
}

# Architecture templates for quick-start
ARCHITECTURE_TEMPLATES = {
    "web_application": {
        "name": "Web Application",
        "description": "Traditional web application with frontend, backend, and database",
        "components": ["Web Browser", "Load Balancer", "Web Server", "Application Server", "Database", "Cache"],
        "data_flows": [
            {"source": "Web Browser", "destination": "Load Balancer", "data": "HTTP Requests", "protocol": "HTTPS"},
            {"source": "Load Balancer", "destination": "Web Server", "data": "Proxied Requests", "protocol": "HTTP/HTTPS"},
            {"source": "Web Server", "destination": "Application Server", "data": "API Calls", "protocol": "HTTP"},
            {"source": "Application Server", "destination": "Database", "data": "Queries/Data", "protocol": "TCP"},
            {"source": "Application Server", "destination": "Cache", "data": "Session/Cache Data", "protocol": "TCP"}
        ],
        "trust_boundaries": [
            {"name": "Internet Boundary", "outside": ["Web Browser"], "inside": ["Load Balancer"]},
            {"name": "DMZ Boundary", "outside": ["Load Balancer"], "inside": ["Web Server"]},
            {"name": "Internal Network", "outside": ["Web Server"], "inside": ["Application Server", "Database", "Cache"]}
        ]
    },
    "rest_api": {
        "name": "REST API Service",
        "description": "API-first service with authentication, business logic, and data layer",
        "components": ["API Client", "API Gateway", "Auth Service", "Business Logic Service", "Database", "Message Queue"],
        "data_flows": [
            {"source": "API Client", "destination": "API Gateway", "data": "API Requests + Auth Tokens", "protocol": "HTTPS"},
            {"source": "API Gateway", "destination": "Auth Service", "data": "Token Validation", "protocol": "gRPC"},
            {"source": "API Gateway", "destination": "Business Logic Service", "data": "Validated Requests", "protocol": "HTTP"},
            {"source": "Business Logic Service", "destination": "Database", "data": "CRUD Operations", "protocol": "TCP"},
            {"source": "Business Logic Service", "destination": "Message Queue", "data": "Async Events", "protocol": "AMQP"}
        ],
        "trust_boundaries": [
            {"name": "Public Internet", "outside": ["API Client"], "inside": ["API Gateway"]},
            {"name": "Service Mesh", "outside": ["API Gateway"], "inside": ["Auth Service", "Business Logic Service"]},
            {"name": "Data Layer", "outside": ["Business Logic Service"], "inside": ["Database", "Message Queue"]}
        ]
    },
    "microservices": {
        "name": "Microservices Architecture",
        "description": "Distributed microservices with service mesh, event-driven communication",
        "components": ["Client App", "API Gateway", "Service A", "Service B", "Service C", "Event Bus", "Database A", "Database B", "Service Registry"],
        "data_flows": [
            {"source": "Client App", "destination": "API Gateway", "data": "Client Requests", "protocol": "HTTPS"},
            {"source": "API Gateway", "destination": "Service A", "data": "Routed Requests", "protocol": "gRPC"},
            {"source": "API Gateway", "destination": "Service B", "data": "Routed Requests", "protocol": "gRPC"},
            {"source": "Service A", "destination": "Event Bus", "data": "Domain Events", "protocol": "AMQP"},
            {"source": "Event Bus", "destination": "Service C", "data": "Event Notifications", "protocol": "AMQP"},
            {"source": "Service A", "destination": "Database A", "data": "Service A Data", "protocol": "TCP"},
            {"source": "Service B", "destination": "Database B", "data": "Service B Data", "protocol": "TCP"}
        ],
        "trust_boundaries": [
            {"name": "External Boundary", "outside": ["Client App"], "inside": ["API Gateway"]},
            {"name": "Service Mesh", "outside": ["API Gateway"], "inside": ["Service A", "Service B", "Service C", "Event Bus", "Service Registry"]},
            {"name": "Data Stores", "outside": ["Service A", "Service B"], "inside": ["Database A", "Database B"]}
        ]
    },
    "mobile_app": {
        "name": "Mobile Application",
        "description": "Mobile app with backend API, push notifications, and third-party integrations",
        "components": ["Mobile App", "CDN", "API Server", "Auth Provider", "Database", "Push Notification Service", "Third-party API"],
        "data_flows": [
            {"source": "Mobile App", "destination": "CDN", "data": "Static Assets", "protocol": "HTTPS"},
            {"source": "Mobile App", "destination": "API Server", "data": "API Requests + JWT", "protocol": "HTTPS"},
            {"source": "Mobile App", "destination": "Auth Provider", "data": "OAuth Flow", "protocol": "HTTPS"},
            {"source": "API Server", "destination": "Database", "data": "User Data / Business Data", "protocol": "TCP"},
            {"source": "API Server", "destination": "Push Notification Service", "data": "Notification Payloads", "protocol": "HTTPS"},
            {"source": "API Server", "destination": "Third-party API", "data": "Integration Data", "protocol": "HTTPS"}
        ],
        "trust_boundaries": [
            {"name": "Device Boundary", "outside": ["Mobile App"], "inside": ["CDN", "API Server"]},
            {"name": "Backend Boundary", "outside": ["API Server"], "inside": ["Database"]},
            {"name": "Third-party Boundary", "outside": ["API Server"], "inside": ["Third-party API", "Push Notification Service"]}
        ]
    },
    "cloud_infrastructure": {
        "name": "Cloud Infrastructure",
        "description": "Cloud-native infrastructure with compute, storage, networking, and IAM",
        "components": ["Users/Admins", "Identity Provider", "VPN Gateway", "VPC", "Compute Instances", "Object Storage", "Managed Database", "Logging Service", "Monitoring"],
        "data_flows": [
            {"source": "Users/Admins", "destination": "Identity Provider", "data": "Authentication Credentials", "protocol": "HTTPS"},
            {"source": "Users/Admins", "destination": "VPN Gateway", "data": "Management Traffic", "protocol": "VPN"},
            {"source": "VPN Gateway", "destination": "VPC", "data": "Internal Traffic", "protocol": "TCP/IP"},
            {"source": "VPC", "destination": "Compute Instances", "data": "Workload Traffic", "protocol": "TCP"},
            {"source": "Compute Instances", "destination": "Object Storage", "data": "File/Blob Data", "protocol": "HTTPS"},
            {"source": "Compute Instances", "destination": "Managed Database", "data": "Application Data", "protocol": "TCP"},
            {"source": "Compute Instances", "destination": "Logging Service", "data": "Logs & Metrics", "protocol": "HTTPS"}
        ],
        "trust_boundaries": [
            {"name": "Cloud Perimeter", "outside": ["Users/Admins"], "inside": ["Identity Provider", "VPN Gateway"]},
            {"name": "VPC Boundary", "outside": ["VPN Gateway"], "inside": ["Compute Instances", "Object Storage", "Managed Database"]},
            {"name": "Management Plane", "outside": ["Compute Instances"], "inside": ["Logging Service", "Monitoring"]}
        ]
    }
}


class DREADScore:
    """DREAD risk scoring for a single threat."""

    def __init__(self, damage=5, reproducibility=5, exploitability=5,
                 affected_users=5, discoverability=5, reasoning=None):
        self.damage = self._clamp(damage)
        self.reproducibility = self._clamp(reproducibility)
        self.exploitability = self._clamp(exploitability)
        self.affected_users = self._clamp(affected_users)
        self.discoverability = self._clamp(discoverability)
        self.reasoning = reasoning or {}

    @staticmethod
    def _clamp(value):
        return max(1, min(10, int(value)))

    @property
    def overall(self):
        return round((self.damage + self.reproducibility + self.exploitability +
                      self.affected_users + self.discoverability) / 5, 1)

    @property
    def risk_level(self):
        score = self.overall
        if score >= 9:
            return "Critical"
        elif score >= 7:
            return "High"
        elif score >= 4:
            return "Medium"
        else:
            return "Low"

    @property
    def risk_color(self):
        return {
            "Critical": "#ff0040",
            "High": "#ff4757",
            "Medium": "#ffa502",
            "Low": "#2ed573"
        }.get(self.risk_level, "#747d8c")

    def to_dict(self):
        return {
            "damage": self.damage,
            "reproducibility": self.reproducibility,
            "exploitability": self.exploitability,
            "affected_users": self.affected_users,
            "discoverability": self.discoverability,
            "overall": self.overall,
            "risk_level": self.risk_level,
            "risk_color": self.risk_color,
            "reasoning": self.reasoning
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            damage=data.get("damage", 5),
            reproducibility=data.get("reproducibility", 5),
            exploitability=data.get("exploitability", 5),
            affected_users=data.get("affected_users", 5),
            discoverability=data.get("discoverability", 5),
            reasoning=data.get("reasoning", {})
        )


class Threat:
    """Individual threat identified through STRIDE analysis."""

    def __init__(self, title, category, description, attack_scenario,
                 affected_component, prerequisites=None, mitigations=None,
                 references=None, dread_score=None, threat_id=None):
        self.id = threat_id or str(uuid.uuid4())[:8]
        self.title = title
        self.category = category  # STRIDE category
        self.description = description
        self.attack_scenario = attack_scenario
        self.affected_component = affected_component
        self.prerequisites = prerequisites or []
        self.mitigations = mitigations or []
        self.references = references or []
        self.dread_score = dread_score or DREADScore()

    def to_dict(self):
        cat_info = STRIDE_CATEGORIES.get(self.category, {})
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "category_icon": cat_info.get("icon", "❓"),
            "category_color": cat_info.get("color", "#747d8c"),
            "security_property": cat_info.get("property", "Unknown"),
            "description": self.description,
            "attack_scenario": self.attack_scenario,
            "affected_component": self.affected_component,
            "prerequisites": self.prerequisites,
            "mitigations": self.mitigations,
            "references": self.references,
            "dread_score": self.dread_score.to_dict()
        }

    @classmethod
    def from_dict(cls, data):
        dread_data = data.get("dread_score", {})
        return cls(
            threat_id=data.get("id"),
            title=data.get("title", "Unknown Threat"),
            category=data.get("category", "Information Disclosure"),
            description=data.get("description", ""),
            attack_scenario=data.get("attack_scenario", ""),
            affected_component=data.get("affected_component", ""),
            prerequisites=data.get("prerequisites", []),
            mitigations=data.get("mitigations", []),
            references=data.get("references", []),
            dread_score=DREADScore.from_dict(dread_data) if dread_data else DREADScore()
        )


class SystemInfo:
    """Information about the system being threat-modeled."""

    def __init__(self, name="", description="", architecture_type="web_application",
                 tech_stack=None, authentication=None, data_sensitivity="Internal",
                 network_exposure="Internet-Facing", data_flows=None,
                 trust_boundaries=None, components=None, existing_controls=None,
                 crown_jewels=None, business_workflows=None, user_roles=None,
                 domain="general"):
        self.name = name
        self.description = description
        self.architecture_type = architecture_type
        self.tech_stack = tech_stack or []
        self.authentication = authentication or []
        self.data_sensitivity = data_sensitivity
        self.network_exposure = network_exposure
        self.data_flows = data_flows or []
        self.trust_boundaries = trust_boundaries or []
        self.components = components or []
        self.existing_controls = existing_controls or []
        self.crown_jewels = crown_jewels or []
        self.business_workflows = business_workflows or []
        self.user_roles = user_roles or []
        self.domain = domain

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "architecture_type": self.architecture_type,
            "tech_stack": self.tech_stack,
            "authentication": self.authentication,
            "data_sensitivity": self.data_sensitivity,
            "network_exposure": self.network_exposure,
            "data_flows": self.data_flows,
            "trust_boundaries": self.trust_boundaries,
            "components": self.components,
            "existing_controls": self.existing_controls,
            "crown_jewels": self.crown_jewels,
            "business_workflows": self.business_workflows,
            "user_roles": self.user_roles,
            "domain": self.domain
        }

    @classmethod
    def from_dict(cls, data):
        return cls(**{k: v for k, v in data.items()
                      if k in cls.__init__.__code__.co_varnames})


class ThreatModel:
    """Complete threat model for a system."""

    def __init__(self, system_info=None):
        self.id = str(uuid.uuid4())[:12]
        self.created_at = datetime.now().isoformat()
        self.system_info = system_info or SystemInfo()
        self.threats = []
        self.metadata = {
            "methodology": "OWASP Threat Modeling + STRIDE + DREAD",
            "version": "1.0",
            "tool": "AI Threat Modeling Assistant"
        }

    def add_threat(self, threat):
        self.threats.append(threat)

    def get_threats_by_category(self):
        categorized = {}
        for cat in STRIDE_CATEGORIES:
            categorized[cat] = [t for t in self.threats if t.category == cat]
        return categorized

    def get_risk_summary(self):
        summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for t in self.threats:
            level = t.dread_score.risk_level
            summary[level] = summary.get(level, 0) + 1
        return summary

    def get_top_risks(self, n=5):
        sorted_threats = sorted(self.threats,
                                key=lambda t: t.dread_score.overall,
                                reverse=True)
        return sorted_threats[:n]

    def to_dict(self):
        return {
            "id": self.id,
            "created_at": self.created_at,
            "system_info": self.system_info.to_dict(),
            "threats": [t.to_dict() for t in self.threats],
            "risk_summary": self.get_risk_summary(),
            "metadata": self.metadata
        }
