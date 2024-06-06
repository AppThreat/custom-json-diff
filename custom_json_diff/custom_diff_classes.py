import contextlib
import logging
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

import semver
import toml
from json_flatten import unflatten  # type: ignore

log = logging.getLogger(__name__)


class BomComponent:
    def __init__(self, comp: Dict, options: "Options"):
        self.version = set_version(comp.get("version", ""), options.allow_new_versions)
        self.search_key = "" if options.allow_new_data else create_comp_key(comp, options.comp_keys)
        self.original_data = comp
        self.component_type = comp.get("type", "")
        self.options = options
        self.name = comp.get("name", "")
        self.group = comp.get("group", "")
        self.publisher = comp.get("publisher", "")
        self.author = comp.get("author", "")
        self.bom_ref = comp.get("bom-ref", "")
        self.purl = comp.get("purl", "")
        self.properties = comp.get("properties", {})
        self.evidence = comp.get("evidence", {})
        self.licenses = comp.get("licenses", [])
        self.hashes = comp.get("hashes", [])
        self.scope = comp.get("scope", [])
        self.description = comp.get("description", "")

    def __eq__(self, other):
        if self.options.allow_new_data:
            return self._advanced_eq(other)
        if self.options.allow_new_versions:
            return self._check_new_versions(other)

        else:
            return self.search_key == other.search_key and self._check_list_eq(other)

    def __ne__(self, other):
        return not self == other

    def _advanced_eq(self, other):
        if self.original_data == other.original_data:
            return True
        if self.options.allow_new_data:
            if self.options.bom_num == 2:
                return self._check_for_empty_eq_other(other)
            return self._check_for_empty_eq(other)
        return False

    def _check_for_empty_eq(self, other):
        if self.name and self.name != other.name:
            return False
        if self.group and self.group != other.group:
            return False
        if self.publisher and self.publisher != other.publisher:
            return False
        if self.bom_ref and self.bom_ref != other.bom_ref:
            return False
        if self.purl and self.purl != other.purl:
            return False
        if self.author and self.author != other.author:
            return False
        if self.component_type and self.component_type != other.component_type:
            return False
        if self.options.allow_new_versions and self.version and not self.version >= other.version:
            return False
        elif self.version and self.version != other.version:
            return False
        if self.properties and self.properties != other.properties:
            return False
        if self.evidence and self.evidence != other.evidence:
            return False
        if self.licenses and self.licenses != other.licenses:
            return False
        if self.hashes and self.hashes != other.hashes:
            return False
        if self.scope and self.scope != other.scope:
            return False
        return not self.description or self.description == other.description

    def _check_for_empty_eq_other(self, other):
        if other.name and other.name != self.name:
            return False
        if other.group and other.group != self.group:
            return False
        if other.publisher and other.publisher != self.publisher:
            return False
        if other.bom_ref and other.bom_ref != self.bom_ref:
            return False
        if other.purl and other.purl != self.purl:
            return False
        if other.author and other.author != self.author:
            return False
        if other.component_type and other.component_type != self.component_type:
            return False
        if other.options.allow_new_versions and other.version and not other.version >= self.version:
            return False
        elif other.version and other.version != self.version:
            return False
        if other.properties and other.properties != self.properties:
            return False
        if other.evidence and other.evidence != self.evidence:
            return False
        if other.licenses and other.licenses != self.licenses:
            return False
        if other.hashes and other.hashes != self.hashes:
            return False
        if other.scope and other.scope != self.scope:
            return False
        return not other.description or other.description == self.description

    def _check_list_eq(self, other):
        if not self.options.allow_new_data:
            return (self.properties == other.properties and self.evidence == other.evidence and
                    self.hashes == other.hashes and self.licenses == other.licenses)
        if self.properties and self.properties != other.properties:
            return False
        if self.evidence and self.evidence != other.evidence:
            return False
        if self.licenses and self.licenses != other.licenses:
            return False
        return not self.hashes or self.hashes == other.hashes

    def _check_new_versions(self, other):
        if self.options.bom_num == 1:
            return self.search_key == other.search_key and self.version <= other.version and self._check_list_eq(other)
        return self.search_key == other.search_key and self.version >= other.version and self._check_list_eq(other)


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
        new_bom_dict = BomDicts(other.options, other.filename, {}, {}, components, services, dependencies)
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
        new_bom_dict = BomDicts(other.options, title or other.filename, {}, {}, components, services, dependencies)
        new_bom_dict.data = self.data.intersection(other.data)
        return new_bom_dict

    def generate_counts(self) -> Dict:
        return {"filename": self.filename, "components": len(self.components), "services": len(self.services), "dependencies": len(self.dependencies)}

    def to_summary(self) -> Dict:
        summary: Dict = {self.filename: {}}
        if self.components:
            summary[self.filename] = {"components": {
                "libraries": [i.original_data for i in self.components if
                    i.component_type == "library"],
                "frameworks": [i.original_data for i in self.components if
                    i.component_type == "framework"],
                "applications": [i.original_data for i in self.components if
                                 i.component_type == "application"], }}
        if not self.options.comp_only:
            if self.data:
                summary[self.filename] |= {"misc_data": self.data.to_dict(unflat=True)}
            if self.services:
                summary[self.filename] |= {"services": [i.original_data for i in self.services]}
            if self.dependencies:
                summary[self.filename] |= {"dependencies": [i.original_data for i in self.dependencies]}
        return summary


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


def check_key(key: str, exclude_keys: Set[str] | List[str]) -> bool:
    return not any(key.startswith(k) for k in exclude_keys)


def create_search_key(key: str, value: str) -> str:
    combined_key = re.sub(r"(?<=\[)[0-9]+(?=])", "", key)
    combined_key += f"|>{value}"
    return combined_key


def create_comp_key(comp: Dict, keys: List[str]) -> str:
    return "|".join([str(comp.get(k, "")) for k in keys])


def get_cdxgen_excludes(includes: List[str], comp_only: bool, allow_new_versions: bool, allow_new_data: bool) -> Tuple[List[str], Set[str], Set[str], bool]:

    excludes = {'metadata.timestamp': 'metadata.timestamp', 'serialNumber': 'serialNumber',
                'metadata.tools.components.[].version': 'metadata.tools.components.[].version',
                'metadata.tools.components.[].purl': 'metadata.tools.components.[].purl',
                'metadata.tools.components.[].bom-ref': 'metadata.tools.components.[].bom-ref',
                'properties': 'components.[].properties', 'evidence': 'components.[].evidence',
                'licenses': 'components.[].licenses', 'hashes': 'components.[].hashes'}
    if comp_only:
        excludes |= {'services': 'services', 'dependencies': 'dependencies'}
    if allow_new_data:
        component_keys = set()
        service_keys = set()
    else:
        component_keys = {'name', 'author', 'publisher', 'group', 'type', 'scope', 'description'}
        service_keys = {'name', 'authenticated', 'x-trust-boundary', 'endpoints'}
        if not allow_new_versions:
            component_keys.add('version')
            component_keys.add('bom-ref')
            component_keys.add('purl')

    return (
        [v for k, v in excludes.items() if k not in includes],
        component_keys,
        service_keys,
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
            logging.error("Invalid TOML.")
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
    with contextlib.suppress(ValueError):
        if allow_new_versions and version:
            version = version.rstrip(".RELEASE")
            return semver.Version.parse(version, True)
    # except ValueError:
    #     log.warning("Could not parse version: %s", version)
    return version
