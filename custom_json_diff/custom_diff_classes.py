import contextlib
import re
from typing import Dict, List, Set, Tuple

import semver
from json_flatten import unflatten  # type: ignore


class BomComponent:
    def __init__(self, comp: Dict, allow_new_versions: bool, component_type: str):
        self.version = set_version(comp.get("version", ""), allow_new_versions)
        self.search_key = create_comp_key(comp, allow_new_versions, component_type)
        self.allow_new_versions = allow_new_versions
        self.original_data = comp
        self.component_type = comp.get("type", "")

    def __eq__(self, other):
        if self.allow_new_versions:
            return self.search_key == other.search_key and self.version >= other.version
        else:
            return self.search_key == other.search_key

    def __ne__(self, other):
        return not self == other


class BomDependency:
    def __init__(self, dep: Dict, allow_new_versions: bool):
        self.ref, self.deps = import_bom_dependency(dep, allow_new_versions)
        self.original_data = dep

    def __eq__(self, other):
        return self.ref == other.ref and self.deps == other.deps

    def __ne__(self, other):
        return not self == other


class BomDicts:
    def __init__(self, allow_new_versions: bool, filename: str, data: Dict | None = None,
                 metadata: Dict | None = None, components: List | None = None,
                 services: List | None = None, dependencies: List | None = None):
        self.data, self.components, self.services, self.dependencies = import_bom_dict(
            allow_new_versions, data, metadata, components, services, dependencies)
        self.filename = filename
        self.allow_new_versions = allow_new_versions

    def __eq__(self, other):
        return (self.data == other.data and self.components == other.components and
                self.services == other.services)

    def __ne__(self, other):
        return not self == other


class FlatDicts:

    def __init__(self, elements: Dict | List):
        self.data = import_flat_dict(elements)

    def __eq__(self, other) -> bool:
        return all(i in other.data for i in self.data) and all(i in self.data for i in other.data)

    def __ne__(self, other) -> bool:
        return not self == other

    def __iadd__(self, other):
        to_add = [i for i in other.data if i not in self.data]
        self.data.extend(to_add)
        return self

    def __isub__(self, other):
        kept_items = [i for i in self.data if i not in other.data]
        self.data = kept_items
        return self

    def __add__(self, other):
        to_add = self.data
        for i in other.data:
            if i not in self.data:
                to_add.append(i)
        return FlatDicts(to_add)

    def __sub__(self, other):
        to_add = [i for i in self.data if i not in other.data]
        return FlatDicts(to_add)

    def to_dict(self, unflat: bool = False) -> Dict:
        result = {i.key: i.value for i in self.data}
        if unflat:
            result = unflatten(result)
        return result

    def intersection(self, other: "FlatDicts") -> "FlatDicts":
        """Returns the intersection of two FlatDicts as a new FlatDicts"""
        intersection = [i for i in self.data if i in other.data]
        return FlatDicts(intersection)

    def filter_out_keys(self, exclude_keys: Set[str]) -> "FlatDicts":
        filtered_data = [i for i in self.data if check_key(i.search_key, exclude_keys)]
        self.data = filtered_data
        return self


class FlatElement:
    def __init__(self, key, value):
        self.key = key
        self.value = value
        self.search_key = create_search_key(key, value)

    def __eq__(self, other):
        return self.search_key == other.search_key


def check_key(key: str, exclude_keys: Set[str]) -> bool:
    return not any(key.startswith(k) for k in exclude_keys)


def create_search_key(key: str, value: str) -> str:
    combined_key = re.sub(r"(?<=\[)[0-9]+(?=])", "", key)
    combined_key += f"|>{value}"
    return combined_key


def create_comp_key(comp: Dict, allow_new_versions: bool, component_type: str) -> str:
    if allow_new_versions:
        if component_type == "components":
            return f"{comp.get('name', '')}|{comp.get('type', '')}|{comp.get('group', '')}|{comp.get('publisher', '')}"
        return f"{comp.get('name', '')}|{comp.get('group', '')}"
    if component_type == "components":
        return f"{comp.get('bom-ref', '')}|{comp.get('name', '')}|{comp.get('purl', '')}|{comp.get('type', '')}|{comp.get('group', '')}|{comp.get('version', '')}|{comp.get('publisher', '')}"
    return f"{comp.get('bom-ref', '')}|{comp.get('name', '')}|{comp.get('group', '')}|{comp.get('version', '')}"


def import_bom_dependency(data: Dict, allow_new_versions: bool):
    ref = data.get("ref", "")
    deps = data.get("dependencies", [])
    if allow_new_versions:
        ref = ref.split("@")[0]
        deps = [i.split("@")[0] for i in deps]
    return ref, set(deps)


def import_bom_dict(
        allow_new_versions: bool, data: Dict | None = None, metadata: Dict | None = None,
        components: List | None = None, services: List | None = None,
        dependencies: List | None = None) -> Tuple[FlatDicts, List, List, List]:
    if data:
        metadata, components, services, dependencies = parse_bom_dict(data, allow_new_versions)
    return FlatDicts(metadata), components, services, dependencies  # type: ignore


def import_flat_dict(data: Dict | List) -> List[FlatElement]:
    if isinstance(data, list):
        return data
    flat_dicts = []
    for key, value in data.items():
        ele = FlatElement(key, value)
        flat_dicts.append(ele)
    return flat_dicts


def parse_bom_dict(data: Dict, allow_new_versions: bool):
    metadata = []
    components = []
    services = []
    dependencies = []
    for key, value in data.items():
        if key not in {"components", "dependencies", "services"}:
            ele = FlatElement(key, value)
            metadata.append(ele)
            continue
        if key == "components":
            for i in value:
                components.append(BomComponent(i, allow_new_versions, "component"))
        elif key == "services":
            for i in value:
                services.append(BomComponent(i, allow_new_versions, "service"))
        elif key == "dependencies":
            for i in value:
                dependencies.append(BomDependency(i, allow_new_versions, ))
    return metadata, components, services, dependencies


def set_version(version: str, allow_new_versions: bool = False) -> semver.Version | str:
    with contextlib.suppress(ValueError):
        if allow_new_versions and version:
            return semver.Version.parse(version, True)
    return version
