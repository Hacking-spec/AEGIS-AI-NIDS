"""
OASIS STIX 2.1 Threat Intelligence Bundle Generator.
Serializes detected intrusions into standardized cybersecurity information sharing bundles.
"""
import uuid
from datetime import datetime
from typing import Dict, Any, List
from backend.app.models.schemas import Alert, StixBundleExport


class Stix21Generator:
    @staticmethod
    def generate_bundle(alert: Alert) -> StixBundleExport:
        """
        Transforms an Alert into an official STIX 2.1 compliant JSON bundle.
        """
        bundle_id = f"bundle--{uuid.uuid4()}"
        now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        # 1. Identity Object (Generating SOC)
        soc_identity_id = "identity--aegis-soc-operations"
        soc_identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": soc_identity_id,
            "created": now_iso,
            "modified": now_iso,
            "name": "Aegis AI Cyber Defense Center",
            "identity_class": "organization",
            "sectors": ["defense", "technology"]
        }

        objects: List[Dict[str, Any]] = [soc_identity]

        # 2. Indicator Object
        src_ip = alert.flow.src_ip
        indicator_id = f"indicator--{uuid.uuid4()}"
        indicator_obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now_iso,
            "modified": now_iso,
            "created_by_ref": soc_identity_id,
            "name": f"Malicious Network Traffic from {src_ip}",
            "description": f"AI-NIDS detected {alert.detection.predicted_class.value} with threat score {alert.detection.threat_score}/100",
            "pattern_type": "stix",
            "pattern": f"[ipv4-addr:value = '{src_ip}']",
            "valid_from": now_iso,
            "confidence": int(alert.detection.confidence * 100),
            "indicator_types": ["malicious-activity", "anomalous-activity"]
        }
        objects.append(indicator_obj)

        # 3. Attack Pattern Objects (from MITRE techniques)
        pattern_refs = []
        for tech in alert.detection.mitre_techniques:
            ap_id = f"attack-pattern--{uuid.uuid4()}"
            pattern_refs.append(ap_id)
            ap_obj = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": now_iso,
                "modified": now_iso,
                "created_by_ref": soc_identity_id,
                "name": tech.name,
                "description": tech.description,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tech.technique_id,
                        "url": tech.url
                    }
                ]
            }
            objects.append(ap_obj)

            # Relationship: indicator indicates attack-pattern
            rel_id = f"relationship--{uuid.uuid4()}"
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": now_iso,
                "modified": now_iso,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": ap_id
            })

        # 4. Threat Actor Object (if enriched from CTI)
        actor_name = alert.threat_intel.threat_actor if alert.threat_intel and alert.threat_intel.threat_actor else "Unattributed Threat Entity"
        actor_id = f"threat-actor--{uuid.uuid4()}"
        actor_obj = {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": actor_id,
            "created": now_iso,
            "modified": now_iso,
            "name": actor_name,
            "threat_actor_types": ["cybercriminal", "state-sponsored"],
            "sophistication": "intermediate"
        }
        objects.append(actor_obj)

        # 5. Course of Action (Mitigation Playbook)
        coa_id = f"course-of-action--{uuid.uuid4()}"
        objects.append({
            "type": "course-of-action",
            "spec_version": "2.1",
            "id": coa_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Isolate & Block {src_ip}",
            "description": f"Automated firewall null-route rule: iptables -I INPUT -s {src_ip} -j DROP",
            "action_type": "block-ip"
        })

        stix_bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects
        }

        return StixBundleExport(
            bundle_id=bundle_id,
            generated_at=datetime.utcnow(),
            objects_count=len(objects),
            stix_json=stix_bundle
        )
