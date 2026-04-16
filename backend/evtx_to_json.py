from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def strip_namespace(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def merge_child(target: dict, key: str, value):
    if key in target:
        existing = target[key]
        if isinstance(existing, list):
            existing.append(value)
        else:
            target[key] = [existing, value]
    else:
        target[key] = value


def xml_element_to_obj(element: ET.Element):
    result: dict[str, object] = {}

    for attr_name, attr_value in element.attrib.items():
        result[f"@{strip_namespace(attr_name)}"] = attr_value

    children = list(element)
    text = (element.text or "").strip()

    if not children:
        if result:
            if text:
                result["#text"] = text
            return result
        return text

    if text:
        result["#text"] = text

    for child in children:
        child_key = strip_namespace(child.tag)
        child_value = xml_element_to_obj(child)
        merge_child(result, child_key, child_value)

    return result


def record_xml_to_json_record(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    return {"Event": {strip_namespace(root.tag): xml_element_to_obj(root)}[strip_namespace(root.tag)]}


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: python evtx_to_json.py <input.evtx> <output.json>")
        return 2

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    if not input_path.exists():
        print(f"[ERROR] Input file not found: {input_path}")
        return 1

    try:
        from Evtx.Evtx import Evtx
    except ImportError as exc:
        print(f"[ERROR] Missing dependency 'python-evtx': {exc}")
        return 1

    converted = 0
    failed = 0

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8") as out_file:
            with Evtx(str(input_path)) as log:
                for record in log.records():
                    try:
                        xml_text = record.xml()
                        json_record = record_xml_to_json_record(xml_text)
                        out_file.write(json.dumps(json_record, ensure_ascii=False) + "\n")
                        converted += 1
                    except Exception:
                        failed += 1
                        continue
    except Exception as exc:
        print(f"[ERROR] Fatal conversion failure: {exc}")
        print(f"[INFO] Input file: {input_path}")
        print(f"[INFO] Output file: {output_path}")
        print(f"[INFO] Records converted: {converted}")
        print(f"[INFO] Records failed: {failed}")
        return 1

    print(f"[INFO] Input file: {input_path}")
    print(f"[INFO] Output file: {output_path}")
    print(f"[INFO] Records converted: {converted}")
    print(f"[INFO] Records failed: {failed}")

    return 0 if converted > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
