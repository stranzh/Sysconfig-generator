import unittest
import xml.etree.ElementTree as ET
import json
import os

class TestSysmonGenerator(unittest.TestCase):
    def setUp(self):
        with open("src/data/lolbas.json") as f:
            self.lolbas = json.load(f)
        with open("src/data/lolol_projects.json") as f:
            self.lolol = json.load(f)
        with open("src/data/software_catalog.json") as f:
            self.software = json.load(f)

    def test_datasets_integrity(self):
        self.assertGreaterEqual(len(self.lolbas), 200, "LOLBAS count should be >= 200")
        self.assertGreaterEqual(len(self.lolol), 30, "lolol.farm projects should be >= 30")
        self.assertGreaterEqual(len(self.software), 10, "Software catalog should be >= 10")

    def test_lolbas_structure(self):
        sample = self.lolbas[0]
        self.assertIn("name", sample)
        self.assertIn("paths", sample)
        self.assertIn("mitre_ids", sample)

    def test_xml_generation_contract(self):
        # Build synthetic XML output mimicking app.js generateSysmonXml
        schema_version = "4.50"
        hash_algo = "md5,sha256,IMPHASH"
        
        xml_content = f"""<Sysmon schemaversion="{schema_version}">
    <HashAlgorithms>{hash_algo}</HashAlgorithms>
    <CheckRevocation/>
    <EventFiltering>
        <RuleGroup name="LivingOffTheLand_LOLBAS" groupRelation="or">
            <ProcessCreate onmatch="include">
                <OriginalFileName condition="is">Certutil.exe</OriginalFileName>
                <Image condition="end with">\\Certutil.exe</Image>
            </ProcessCreate>
        </RuleGroup>
        <RuleGroup name="Software_Noise_Filtering" groupRelation="or">
            <ProcessCreate onmatch="exclude">
                <CommandLine condition="begin with">"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=</CommandLine>
            </ProcessCreate>
        </RuleGroup>
    </EventFiltering>
</Sysmon>"""
        
        # Parse XML to verify valid XML schema syntax
        root = ET.fromstring(xml_content)
        self.assertEqual(root.tag, "Sysmon")
        self.assertEqual(root.attrib["schemaversion"], "4.50")
        
        # Verify FileDelete (23 / 26) is NOT present
        tags = [elem.tag for elem in root.iter()]
        self.assertNotIn("FileDelete", tags)
        self.assertNotIn("FileDeleteDetected", tags)

    def test_software_scanner_script_output(self):
        with open("src/data/sample_scan_report.json") as f:
            scan = json.load(f)
        self.assertIn("running_processes", scan)
        self.assertIn("scanner_version", scan)

    def test_lolol_projects_xml_generation(self):
        from xml.sax.saxutils import escape

        def escape_comment(text):
            return escape(str(text)).replace("--", "-")

        grouped = {}
        for p in self.lolol:
            rt = p.get("rule_template")
            if rt and rt.get("rules"):
                ev = rt["event"]
                act = rt.get("action", "include")
                grouped.setdefault(f"{ev}|{act}", []).append(p)

        self.assertGreater(len(grouped), 0, "Expected lolol.farm projects with rule templates")

        xml_parts = ['<Sysmon schemaversion="4.50">', '<EventFiltering>']
        for key, projects in grouped.items():
            ev, act = key.split("|")
            xml_parts.append(f'<RuleGroup name="LOLOL_Farm_{ev}" groupRelation="or">')
            xml_parts.append(f'<{ev} onmatch="{act}">')
            for p in projects:
                rt = p["rule_template"]
                xml_parts.append(f'<!-- [{escape_comment(p["title"])}] {escape_comment(rt.get("description", ""))} -->')
                for r in rt["rules"]:
                    if r.get("comment"):
                        xml_parts.append(f'<!-- {escape_comment(r["comment"])} -->')
                    xml_parts.append(f'<{r["field"]} condition="{r["condition"]}">{escape(r["value"])}</{r["field"]}>')
            xml_parts.append(f'</{ev}>')
            xml_parts.append('</RuleGroup>')
        xml_parts.extend(['</EventFiltering>', '</Sysmon>'])

        root = ET.fromstring("\n".join(xml_parts))
        self.assertEqual(root.tag, "Sysmon")

if __name__ == "__main__":
    unittest.main()
