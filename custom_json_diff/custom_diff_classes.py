import logging
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

import semver
import toml
from json_flatten import unflatten  # type: ignore


logger = logging.getLogger(__name__)


class BomComponent:
    def __init__(self, comp: Dict, options: "Options"):
        self.author = comp.get("author", "")
        self.bom_ref = comp.get("bom-ref", "")
        self.component_type = comp.get("type", "")
        self.description = comp.get("description", "")
        self.evidence = comp.get("evidence", {})
        self.external_references = comp.get("externalReferences", [])
        self.group = comp.get("group", "")
        self.hashes = comp.get("hashes", [])
        self.licenses = comp.get("licenses", [])
        self.name = comp.get("name", "")
        self.options = options
        self.original_data = comp
        self.properties = comp.get("properties", [])
        self.publisher = comp.get("publisher", "")
        self.purl = comp.get("purl", "")
        self.scope = comp.get("scope", [])
        self.search_key = "" if options.allow_new_data else create_comp_key(comp, options.comp_keys)
        self.version = set_version(comp.get("version", ""), options.allow_new_versions)

    def __eq__(self, other):
        if self.options.allow_new_versions and self.options.allow_new_data:
            return self._advanced_eq(other) and self._check_new_versions(other)
        if self.options.allow_new_versions:
            return self._check_new_versions(other) and self._check_list_eq(other) and self.search_key == other.search_key
        if self.options.allow_new_data:
            return self._advanced_eq(other)
        else:
            return self.search_key == other.search_key and self._check_list_eq(other)

    def __ne__(self, other):
        return not self == other

    def _advanced_eq(self, other):
        if self.original_data == other.original_data:
            return True
        if self.options.bom_num == 1:
            return check_for_empty_eq(self, other)
        return check_for_empty_eq(other, self)

    def _check_list_eq(self, other):
        # Since these elements have been sorted, we can compare them directly
        return (self.properties == other.properties and self.evidence == other.evidence and
                self.hashes == other.hashes and self.licenses == other.licenses)

    def _check_new_versions(self, other):
        if self.options.bom_num == 1:
            return self.version <= other.version
        return self.version >= other.version


class BomDependency:
    def __init__(self, dep: Dict, options: "Options"):
        self.ref, self.deps = import_bom_dependency(dep, options.allow_new_versions)
        self.original_data = {"ref": self.ref, "dependsOn": self.deps}

    def __eq__(self, other):
        return self.ref == other.ref and self.deps == other.deps

    def __ne__(self, other):
        return not self == other


class BomDicts:
    def __init__(self, options: "Options", filename: str, data: Dict,
                 metadata: Dict, components: List | None = None,
                 services: List | None = None, dependencies: List | None = None):
        self.options = options
        self.options.bom_num = 1 if filename == options.file_1 else 2
        self.data, self.components, self.services, self.dependencies = import_bom_dict(
            self.options, data, metadata, components, services, dependencies)
        self.filename = filename

    def __eq__(self, other):
        return (self.data == other.data and self.components == other.components and
                self.services == other.services and self.dependencies == other.dependencies)

    def __ne__(self, other):
        return not self == other

    def __sub__(self, other):
        data = (other.data - self.data)
        components = []
        services = []
        dependencies = []
        if other.components:
            components = [i for i in other.components if i not in self.components]
        if other.services:
            services = [i for i in other.services if i not in self.services]
        if other.dependencies:
            dependencies = [i for i in other.dependencies if i not in self.dependencies]
        new_bom_dict = BomDicts(
            other.options,
            other.filename,
            {},
            {},
            components,
            services,
            dependencies
        )
        if new_bom_dict.filename == new_bom_dict.options.file_1:
            new_bom_dict.options.bom_num = 1
        new_bom_dict.data = data
        return new_bom_dict

    def intersection(self, other, title: str = "") -> "BomDicts":
        components = []
        services = []
        dependencies = []
        if self.components:
            components = [i for i in other.components if i in self.components]
        if self.services:
            services = [i for i in other.services if i in self.services]
        if self.dependencies:
            dependencies = [i for i in other.dependencies if i in self.dependencies]
        new_bom_dict = BomDicts(
            other.options,
            title or other.filename,
            {},
            {},
            components,
            services,
            dependencies
        )
        new_bom_dict.data = self.data.intersection(other.data)
        return new_bom_dict

    def generate_counts(self) -> Dict:
        lib = 0
        frameworks = 0
        apps = 0
        other = 0
        for i in self.components:
            if i.component_type == "library":
                lib += 1
            elif i.component_type == "framework":
                frameworks += 1
            elif i.component_type == "application":
                apps += 1
            else:
                other += 1
        return {"components": len(self.components), "applications": apps,
                "frameworks": frameworks, "libraries": lib, "other_components": other,
                "services": len(self.services), "dependencies": len(self.dependencies)}

    def to_summary(self) -> Dict:
        summary: Dict = {self.filename: {}}
        if self.components:
            summary[self.filename] = {"components": {
                "libraries": [i.original_data for i in self.components if
                              i.component_type == "library"],
                "frameworks": [i.original_data for i in self.components if
                               i.component_type == "framework"],
                "applications": [i.original_data for i in self.components if
                                 i.component_type == "application"],
                "other_components": [i.original_data for i in self.components if
                                     i.component_type not in (
                                         "library", "framework", "application")], }}
        if not self.options.comp_only:
            if self.data:
                summary[self.filename] |= {"misc_data": self.data.to_dict(unflat=True)}
            if self.services:
                summary[self.filename] |= {"services": [i.original_data for i in self.services]}
            if self.dependencies:
                summary[self.filename] |= {"dependencies": [
                    i.original_data for i in self.dependencies]}
        return summary


class BomService:
    def __init__(self, svc: Dict, options: "Options"):
        self.search_key = "" if options.allow_new_data else create_comp_key(svc, options.svc_keys)
        self.original_data = svc
        self.name = svc.get("name", "")
        self.endpoints = svc.get("endpoints", [])
        self.authenticated = svc.get("authenticated", "")
        self.x_trust_boundary = svc.get("x-trust-boundary", "")

    def __eq__(self, other):
        return self.search_key == other.search_key and self.endpoints == other.endpoints

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

    def filter_out_keys(self, exclude_keys: Set[str] | List[str]) -> "FlatDicts":
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


@dataclass
class Options:  # type: ignore
    allow_new_data: bool = False
    allow_new_versions: bool = False
    bom_diff: bool = False
    comp_only: bool = False
    config: str = ""
    exclude: List = field(default_factory=list)
    file_1: str = ""
    file_2: str = ""
    include: List = field(default_factory=list)
    output: str = ""
    report_template: str = ""
    sort_keys: List = field(default_factory=list)
    testing: bool = False
    comp_keys: List = field(default_factory=list)
    svc_keys: List = field(default_factory=list)
    bom_num: int = 1

    def __post_init__(self):
        if self.testing:
            self.exclude, self.comp_keys, self.svc_keys, self.do_advanced = get_cdxgen_excludes(
                self.include, self.comp_only, self.allow_new_versions, self.allow_new_data)
            self.sort_keys = ["url", "content", "ref", "name", "value", "location"]
        elif self.config:
            toml_data = import_config(self.config)
            self.allow_new_versions = toml_data.get("bom_diff", {}).get(
                "allow_new_versions", False)
            self.allow_new_data = toml_data.get("bom_diff", {}).get("allow_new_data", False)
            self.report_template = toml_data.get("bom_diff", {}).get("report_template", "")
            self.sort_keys = toml_data.get("settings", {}).get("sort_keys", [])
            self.exclude = toml_data.get("settings", {}).get("excluded_fields", [])
            self.include = toml_data.get("settings", {}).get("include_extra", [])
            self.comp_only = toml_data.get("bom_diff", {}).get("components_only", False)
        if self.bom_diff:
            tmp_exclude, tmp_bom_key_fields, tmp_service_key_fields, self.do_advanced = (
                get_cdxgen_excludes(
                    self.include, self.comp_only, self.allow_new_versions, self.allow_new_data))
            self.comp_keys.extend(tmp_bom_key_fields)
            self.svc_keys.extend(tmp_service_key_fields)
            self.exclude.extend(tmp_exclude)
            self.sort_keys.extend(["url", "content", "ref", "name", "value", "location"])
        self.exclude = list(set(self.exclude))
        self.include = list(set(self.include))
        self.comp_keys = list(set(self.comp_keys))
        self.svc_keys = list(set(self.svc_keys))


def advanced_eq_lists(bom_1: List, bom_2: List) -> bool:
    return False if len(bom_1) > len(bom_2) else all(i in bom_2 for i in bom_1)


def check_for_empty_eq(bom_1: BomComponent, bom_2: BomComponent) -> bool:
    if bom_1.name and bom_1.name != bom_2.name:
        return False
    if bom_1.group and bom_1.group != bom_2.group:
        return False
    if bom_1.publisher and bom_1.publisher != bom_2.publisher:
        return False
    if bom_1.author and bom_1.author != bom_2.author:
        return False
    if bom_1.component_type and bom_1.component_type != bom_2.component_type:
        return False
    if bom_1.scope and bom_1.scope != bom_2.scope:
        return False
    if not bom_1.options.allow_new_versions:
        if bom_1.version and bom_1.version != bom_2.version:
            return False
        if bom_1.bom_ref and bom_1.bom_ref != bom_2.bom_ref:
            return False
        if bom_1.purl and bom_1.purl != bom_2.purl:
            return False
        if not advanced_eq_lists(bom_1.hashes, bom_2.hashes):
            return False
    if not advanced_eq_lists(bom_1.properties, bom_2.properties):
        return False
    if not advanced_eq_lists(bom_1.licenses, bom_2.licenses):
        return False
    if not advanced_eq_lists(bom_1.external_references, bom_2.external_references):
        return False
    if bom_1.evidence and bom_1.evidence != bom_2.evidence:
        return False
    return not bom_1.description or bom_1.description == bom_2.description


def check_key(key: str, exclude_keys: Set[str] | List[str]) -> bool:
    return not any(key.startswith(k) for k in exclude_keys)


def create_comp_key(comp: Dict, keys: List[str]) -> str:
    return "|".join([str(comp.get(k, "")) for k in keys])


def create_search_key(key: str, value: str) -> str:
    combined_key = re.sub(r"(?<=\[)[0-9]+(?=])", "", key)
    combined_key += f"|>{value}"
    return combined_key


def get_cdxgen_excludes(includes: List[str], comp_only: bool, allow_new_versions: bool,
                        allow_new_data: bool) -> Tuple[List[str], List[str], List[str], bool]:

    excludes = {'metadata.timestamp': 'metadata.timestamp', 'serialNumber': 'serialNumber',
                'metadata.tools.components.[].version': 'metadata.tools.components.[].version',
                'metadata.tools.components.[].purl': 'metadata.tools.components.[].purl',
                'metadata.tools.components.[].bom-ref': 'metadata.tools.components.[].bom-ref',
                'properties': 'components.[].properties', 'evidence': 'components.[].evidence',
                'licenses': 'components.[].licenses', 'hashes': 'components.[].hashes',
                'externalReferences': 'components.[].externalReferences',
                'externalreferences': 'components.[].externalReferences'}
    if comp_only:
        excludes |= {'services': 'services', 'dependencies': 'dependencies'}
    if allow_new_data:
        component_keys = []
        service_keys = []
    else:
        component_keys = ['name', 'author', 'publisher', 'group', 'type', 'scope', 'description']
        service_keys = ['name', 'authenticated', 'x-trust-boundary', 'endpoints']
        if not allow_new_versions:
            component_keys.extend([i for i in ('version', 'purl', 'bom-ref', 'version') if i not in excludes])

    return (
        [v for k, v in excludes.items() if k not in includes],
        [v for v in component_keys if v not in excludes],
        [v for v in service_keys if v not in excludes],
        allow_new_data,
    )


def import_bom_dependency(data: Dict, allow_new_versions: bool) -> Tuple[str, List]:
    ref = data.get("ref", "")
    deps = data.get("dependsOn", [])
    if allow_new_versions:
        ref = ref.split("@")[0]
        deps = [i.split("@")[0] for i in deps]
    return ref, deps


def import_bom_dict(
        options: Options, data: Dict, metadata: Dict | List,
        components: List | None = None, services: List | None = None,
        dependencies: List | None = None) -> Tuple[FlatDicts, List, List, List]:
    if data:
        metadata, components, services, dependencies = parse_bom_dict(data, options)
    if not components:
        components = []
    if not services:
        services = []
    if not dependencies:
        dependencies = []
    return FlatDicts(metadata), components, services, dependencies  # type: ignore


def import_config(config: str) -> Dict:
    with open(config, "r", encoding="utf-8") as f:
        try:
            toml_data = toml.load(f)
        except toml.TomlDecodeError:
            logger.error("Invalid TOML.")
            sys.exit(1)
    return toml_data


def import_flat_dict(data: Dict | List) -> List[FlatElement]:
    if isinstance(data, list):
        return data
    flat_dicts = []
    for key, value in data.items():
        ele = FlatElement(key, value)
        flat_dicts.append(ele)
    return flat_dicts


def parse_bom_dict(data: Dict, options: "Options") -> Tuple[List, List, List, List]:
    metadata = []
    services: List = []
    dependencies: List = []
    components = [
        BomComponent(i, options)
        for i in data.get("components", [])
    ]
    if not options.comp_only:
        services.extend(BomService(i, options) for i in data.get("services", []))
        dependencies.extend(BomDependency(i, options) for i in data.get("dependencies", []))
        for key, value in data.items():
            if key not in {"components", "dependencies", "services"}:
                ele = FlatElement(key, value)
                metadata.append(ele)
    return metadata, components, services, dependencies


def set_version(version: str, allow_new_versions: bool = False) -> semver.Version | str:
    try:
        if allow_new_versions and version:
            version = version.lstrip("v").rstrip(".RELEASE")
            return semver.Version.parse(version, True)
    except ValueError:
        logger.debug("Could not parse version: %s", version)
    return version
