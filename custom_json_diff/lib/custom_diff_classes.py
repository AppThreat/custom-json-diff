import logging
import re
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from json_flatten import unflatten  # type: ignore

from custom_json_diff.lib.utils import (
    compare_bom_refs, compare_date, compare_recommendations, compare_versions, import_config
)


logger = logging.getLogger(__name__)


@dataclass
class Options:  # type: ignore
    allow_new_data: bool = False
    allow_new_versions: bool = False
    preconfig_type: str = ""
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
    doc_num: int = 1

    def __post_init__(self):
        if self.testing:
            self.exclude, self.comp_keys, self.svc_keys, self.do_advanced = get_cdxgen_excludes(
                self.include, self.allow_new_versions, self.allow_new_data)
            self.sort_keys = ["url", "content", "ref", "name", "value", "location"]
        elif self.config:
            toml_data = import_config(self.config)
            self.preconfig_type = toml_data.get("preset_settings", {}).get("type", "")
            self.allow_new_versions = toml_data.get("preset_settings", {}).get(
                "allow_new_versions", False)
            self.allow_new_data = toml_data.get("preset_settings", {}).get("allow_new_data", False)
            self.report_template = toml_data.get("preset_settings", {}).get("report_template", "")
            self.sort_keys = toml_data.get("settings", {}).get("sort_keys", [])
            self.exclude = toml_data.get("settings", {}).get("excluded_fields", [])
            self.include = toml_data.get("settings", {}).get("include_extra", [])
        if self.preconfig_type == "bom":
            tmp_exclude, tmp_bom_key_fields, tmp_service_key_fields, self.do_advanced = (
                get_cdxgen_excludes(self.include, self.allow_new_versions, self.allow_new_data))
            self.comp_keys.extend(tmp_bom_key_fields)
            self.svc_keys.extend(tmp_service_key_fields)
            self.exclude.extend(tmp_exclude)
            self.sort_keys.extend(["purl", "bom-ref", "content", "cve", "id", "url", "text", "ref", "name", "value", "location"])
        elif self.preconfig_type == "csaf":
            self.exclude.extend(["document.tracking"])
            self.sort_keys.extend(["title", "text", "product_id", "url"])
        self.exclude = list(set(self.exclude))
        self.include = list(set(self.include))
        self.comp_keys = list(set(self.comp_keys))
        self.svc_keys = list(set(self.svc_keys))


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

    def to_dict(self):
        return {self.key: self.value}


class BomComponent:
    def __init__(self, comp: Dict, options: Options):
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
        self.version = comp.get("version", "")

    def __eq__(self, other):
        c1, c2 = order_documents(self, other)
        if self.options.allow_new_versions and self.options.allow_new_data:
            return eq_allow_new_data_comp(c1, c2)
        if self.options.allow_new_versions:
            return all((
                compare_versions(c1.version, c2.version, "<="), self._check_list_eq(other),
                compare_bom_refs(c1.bom_ref, c2.bom_ref, "<="), compare_bom_refs(c1.purl, c2.purl, "<=")
            ))
        if self.options.allow_new_data:
            return eq_allow_new_data_comp(c1, c2)
        return self.search_key == other.search_key and self._check_list_eq(other)

    def __ne__(self, other):
        return not self == other

    def _check_list_eq(self, other):
        # Since these elements have been sorted, we can compare them directly
        return (self.properties == other.properties and self.evidence == other.evidence and
                self.hashes == other.hashes and self.licenses == other.licenses)

    def to_dict(self):
        return {"author": self.author, "bom-ref": self.bom_ref, "type": self.component_type,
                "description": self.description, "evidence": self.evidence,
                "externalReferences": self.external_references, "group": self.group,
                "hashes": self.hashes, "licenses": self.licenses, "name": self.name,
                "properties": self.properties, "publisher": self.publisher, "purl": self.purl,
                "scope": self.scope, "version": self.version}


class BomDependency:
    def __init__(self, dep: Dict, options: "Options"):
        self.ref, self.deps = import_bom_dependency(dep, options.allow_new_versions)
        self.original_data = {"ref": self.ref, "dependsOn": self.deps}
        self.options = options

    def __eq__(self, other):
        return self.ref == other.ref and self.deps == other.deps

    def __ne__(self, other):
        return not self == other

    def to_dict(self):
        return {"ref": self.ref, "dependsOn": self.deps}


class BomDicts:
    def __init__(self, options: "Options", filename: str, original_data: Dict, other_data: FlatDicts | None = None,
                 components: List | None = None, services: List | None = None,
                 dependencies: List | None = None, vulnerabilities: List | None = None):
        self.options = options
        self.options.doc_num = 1 if filename == options.file_1 else 2
        self.other_data, self.components, self.services, self.dependencies, self.vdrs = import_bom_dict(
            self.options, original_data, other_data, components, services, dependencies, vulnerabilities)
        self.filename = filename

    def __eq__(self, other):
        return (self.other_data == other.other_data and self.components == other.components and
                self.services == other.services and self.dependencies == other.dependencies and
                self.vdrs == self.vdrs)

    def __ne__(self, other):
        return not self == other

    def __sub__(self, other):
        other_data = self.other_data - other.other_data
        components = self.components
        services = self.services
        dependencies = self.dependencies
        vulnerabilities = self.vdrs
        if other.filename == "common_summary":
            other.options.doc_num = 2
            self.options.doc_num = 1
        if other.components:
            components = [i for i in self.components if i not in other.components]
        if other.services:
            services = [i for i in self.services if i not in other.services]
        if other.dependencies:
            dependencies = [i for i in self.dependencies if i not in other.dependencies]
        if other.vdrs:
            vulnerabilities = [i for i in self.vdrs if i not in other.vdrs]
        filename = self.filename
        options = deepcopy(self.options)
        new_bom_dict = BomDicts(
            options,
            filename,
            {},
            FlatDicts(other_data),
            components=components,
            services=services,
            dependencies=dependencies,
            vulnerabilities=vulnerabilities
        )
        if new_bom_dict.filename == new_bom_dict.options.file_1:
            new_bom_dict.options.doc_num = 1
        return new_bom_dict

    def intersection(self, other, title: str = "") -> "BomDicts":
        components = []
        dependencies = []
        services = []
        vulnerabilities = []
        if self.components and other.components:
            components = [i for i in self.components if i in other.components]
        if self.services and other.services:
            services = [i for i in self.services if i in other.services]
        if self.dependencies and other.dependencies:
            dependencies = [i for i in self.dependencies if i in other.dependencies]
        if self.vdrs and other.vdrs:
            vulnerabilities = [i for i in self.vdrs if i in other.vdrs]
        other_data = self.other_data.intersection(other.other_data)
        options = deepcopy(self.options)
        return BomDicts(
            options,
            title or other.filename,
            {},
            other_data=other_data,
            components=components,
            services=services,
            dependencies=dependencies,
            vulnerabilities=vulnerabilities
        )

    def generate_comp_counts(self) -> Dict:
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
                "services": len(self.services), "dependencies": len(self.dependencies),
                "vulnerabilities": len(self.vdrs)}

    def get_refs(self) -> Dict:
        return {
            "components": {i.bom_ref for i in self.components},
            "dependencies": {i.ref for i in self.dependencies},
            "services": {i.search_key for i in self.services},
            "vdrs": {i.bom_ref for i in self.vdrs}
        }

    def to_summary(self) -> Dict:
        summary: Dict = {self.filename: {}}
        if self.components:
            summary[self.filename] = {"components": {
                "libraries": [i.to_dict() for i in self.components if
                              i.component_type == "library"],
                "frameworks": [i.to_dict() for i in self.components if
                               i.component_type == "framework"],
                "applications": [i.to_dict() for i in self.components if
                                 i.component_type == "application"],
                "other_components": [i.to_dict() for i in self.components if
                                     i.component_type not in (
                                         "library", "framework", "application")], }}
        if self.other_data:
            summary[self.filename] |= {"misc_data": self.other_data.to_dict(unflat=True)}
        if self.services:
            summary[self.filename] |= {"services": [i.to_dict() for i in self.services]}
        if self.dependencies:
            summary[self.filename] |= {"dependencies": [
                i.to_dict() for i in self.dependencies]}
        if self.vdrs:
            summary[self.filename] |= {"vulnerabilities": [i.to_dict() for i in self.vdrs]}
        return summary


class BomService:
    def __init__(self, svc: Dict, options: "Options"):
        self.search_key = create_comp_key(svc, options.svc_keys)
        self.original_data = svc
        self.name = svc.get("name", "")
        self.endpoints = svc.get("endpoints", [])
        self.authenticated = svc.get("authenticated", "")
        self.x_trust_boundary = svc.get("x-trust-boundary", "")

    def __eq__(self, other):
        return self.search_key == other.search_key and self.endpoints == other.endpoints

    def __ne__(self, other):
        return not self == other

    def to_dict(self):
        return {
            "name": self.name,
            "endpoints": self.endpoints,
            "authenticated": self.authenticated,
            "x-trust-boundary": self.x_trust_boundary
        }


@dataclass
class BomVdr:
    """Class for holding bom vulnerability data"""
    id: str = ""
    bom_ref: str = ""
    advisories: list = field(default_factory=list)
    affects: List = field(default_factory=list)
    analysis: Dict = field(default_factory=dict)
    cwes: List = field(default_factory=list)
    data: Dict = field(default_factory=dict)
    description: str = ""
    detail: str = ""
    properties: List = field(default_factory=list)
    published: str = ""
    ratings: list = field(default_factory=list)
    recommendation: str = ""
    references: list = field(default_factory=list)
    source: Dict = field(default_factory=dict)
    updated: str = ""
    options: "Options" = field(default_factory=lambda: Options())  # type: ignore

    def __post_init__(self):
        if not self.options:
            self.options = Options()
        self.id = self.id or (self.data.get("id") or "")
        self.bom_ref = self.bom_ref or (self.data.get("bom-ref") or "")
        self.advisories = self.advisories or (self.data.get("advisories") or [])
        self.affects = self.affects or (self.data.get("affects") or [])
        if self.affects and not isinstance(self.affects[0], BomVdrAffects):
            self.affects = [BomVdrAffects(i, self.options) for i in self.affects]
        self.analysis = self.analysis or (self.data.get("analysis") or {})
        self.cwes = self.cwes or (self.data.get("cwes") or [])
        self.description = self.description or (self.data.get("description") or "")
        self.detail = self.detail or (self.data.get("detail") or "")
        self.properties = self.properties or (self.data.get("properties") or [])
        self.published = self.published or (self.data.get("published") or "")
        self.ratings = self.ratings or (self.data.get("ratings") or [])
        self.recommendation = self.recommendation or (self.data.get("recommendation") or "")
        self.references = self.references or (self.data.get("references") or [])
        self.source = self.source or (self.data.get("source") or {})
        self.updated = self.updated or (self.data.get("updated") or "")

    def __eq__(self, other):
        if self.affects and not isinstance(self.affects[0], BomVdrAffects):
            self.affects = [BomVdrAffects(i, self.options) for i in self.affects]
        if not self.options.allow_new_data and not self.options.allow_new_versions:
            return all((self._field_eq(other), self.bom_ref == other.bom_ref,
                        self.affects == other.affects, self.updated == other.updated))
        b1, b2 = order_documents(self, other)
        if self.options.allow_new_data:
            # eq_allow_new_data_vdr checks for allow_new_versions as well
            return eq_allow_new_data_vdr(b1, b2)
        return self._field_eq(other) and compare_vdr_new_versions(b1, b2)

    def __ne__(self, other):
        return not self == other

    def _field_eq(self, other):
        """Compare fields that aren't affected by allow_new_versions
        excludes bom-ref, affects, updated"""
        return all((
            self.id == other.id,
            self.advisories == other.advisories,
            self.analysis == other.analysis,
            self.cwes == other.cwes,
            self.description == other.description,
            self.detail == other.detail,
            self.properties == other.properties,
            self.published == other.published,
            self.ratings == other.ratings,
            self.recommendation == other.recommendation,
            self.references == other.references,
            self.source == other.source,
            ))

    def clear(self):
        options = self.options
        self.__init__()
        self.options = options

    def to_dict(self):
        return {
            "id": self.id,
            "bom-ref": self.bom_ref,
            "advisories": self.advisories, 
            "affects": [i.to_dict() for i in self.affects],
            "analysis": self.analysis,
            "cwes": self.cwes,
            "description": self.description,
            "detail": self.detail,
            "properties": self.properties,
            "published": self.published,
            "ratings": self.ratings,
            "recommendation": self.recommendation,
            "references": self.references,
            "source": self.source, 
            "updated": self.updated,
        }


class BomVdrAffects:
    def __init__(self, data: Dict, options: "Options"):
        self.data = data
        self.options = options
        self.ref = data.get("ref", "")
        self.versions = data.get("", [])

    def __eq__(self, other):
        if self.data == other.data:
            return True
        a1, a2 = order_documents(self, other)
        if self.options.allow_new_data and self.options.allow_new_versions:
            if a1.ref and not compare_bom_refs(a1.ref, a2.ref, "<="):
                return False
            if a1.versions and not advanced_eq_lists(a1.versions, a2.versions):
                return False
        elif self.options.allow_new_versions:
            return compare_bom_refs(a1.ref, a2.ref, "<=") and advanced_eq_lists(a1.versions, a2.versions)
        return False

    def __ne__(self, other):
        return not self == other

    def to_dict(self):
        return {"ref": self.ref, "versions": self.versions}


class CsafDicts:
    def __init__(self, options: "Options", filename: str, original_data: Dict | None = None,
                 document: FlatDicts | None = None, product_tree: FlatDicts | None = None,
                 vulnerabilities: List | None = None):
        self.document, self.product_tree, self.vulnerabilities = import_csaf(
            options, original_data, document, product_tree, vulnerabilities)
        self.options = options
        self.options.doc_num = 1 if filename == options.file_1 else 2
        self.filename = filename

    def __eq__(self, other):
        return all((
            self.document == other.document,
            self.product_tree == other.product_tree,
            self.vulnerabilities == other.vulnerabilities
        ))

    def __ne__(self, other):
        return not self == other

    def __sub__(self, other):
        document = self.document - other.document
        product_tree = self.product_tree - other.product_tree
        vulnerabilities = [i for i in self.vulnerabilities if i not in other.vulnerabilities]
        filename = self.filename
        options = deepcopy(self.options)
        return CsafDicts(
            options,
            filename,
            {},
            document=document,
            product_tree=product_tree,
            vulnerabilities=vulnerabilities
        )

    def get_refs(self):
        return {"vulnerabilities": {i.title for i in self.vulnerabilities}}

    def intersection(self, other, title: str = "") -> "CsafDicts":
        document = self.document.intersection(other.document)
        product_tree = self.product_tree.intersection(other.product_tree)
        vulnerabilities = [i for i in self.vulnerabilities if i in other.vulnerabilities]
        options = deepcopy(self.options)
        return CsafDicts(
            options,
            title or other.filename,
            {},
            document=document,
            product_tree=product_tree,
            vulnerabilities=vulnerabilities
        )

    def to_dict(self):
        return {
            "document": self.document.to_dict(unflat=True) if self.document else {},
            "product_tree": self.product_tree.to_dict(unflat=True) if self.product_tree else {},
            "vulnerabilities": [i.to_dict() for i in self.vulnerabilities] if self.vulnerabilities else []
        }

    def to_summary(self) -> Dict:
        return {self.filename: self.to_dict()}


class CsafVulnerability:
    def __init__(self, data: Dict, options: "Options"):
        self.acknowledgements = data.get("acknowledgements", [])
        self.cve = data.get("cve", "")
        self.cwe = data.get("cwe", "")
        self.discovery_date = data.get("discovery_date", "")
        self.ids = data.get("ids", [])
        self.notes = data.get("notes", [])
        self.options = options
        self.product_status = data.get("product_status", {})
        self.references = data.get("references", [])
        self.scores = data.get("scores", [])
        self.title = data.get("title", "")

    def __eq__(self, other):
        if not self.options.allow_new_data:
            return self.to_dict() == other.to_dict()
        attributes_to_compare = [('cve', lambda self, other: self.cve == other.cve),
            ('cwe', lambda self, other: self.cwe == other.cwe),
            ('discovery_date', lambda self, other: self.discovery_date == other.discovery_date),
            ('product_status', lambda self, other: self.product_status == other.product_status), (
            'acknowledgements',
            lambda self, other: advanced_eq_lists(self.acknowledgements, other.acknowledgements)),
            ('ids', lambda self, other: advanced_eq_lists(self.ids, other.ids)),
            ('notes', lambda self, other: advanced_eq_lists(self.notes, other.notes)), (
            'references',
            lambda self, other: advanced_eq_lists(self.references, other.references)),
            ('scores', lambda self, other: advanced_eq_lists(self.scores, other.scores)),
            ('title', lambda self, other: self.title == other.title),]
        return not any(
            getattr(self, attr) and not compare(self, other)
            for attr, compare in attributes_to_compare
        )

    def __ne__(self, other):
        return not self == other

    def to_dict(self):
        return {
            "acknowledgements": self.acknowledgements,
            "cve": self.cve,
            "cwe": self.cwe,
            "discovery_date": self.discovery_date,
            "ids": self.ids,
            "notes": self.notes,
            "product_status": self.product_status,
            "references": self.references,
            "scores": self.scores,
            "title": self.title
        }


def advanced_eq_lists(lst_1: List, lst_2: List) -> bool:
    """Checks that all items in bom_1 are in bom_2 when allow_new_data is True"""
    return False if len(lst_1) > len(lst_2) else all(i in lst_2 for i in lst_1)


def eq_allow_new_data_comp(bom_1: BomComponent, bom_2: BomComponent) -> bool:
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
    if bom_1.options.allow_new_versions:
        if bom_1.version and bom_1.version > bom_2.version:
            return False
        if bom_1.bom_ref and not compare_bom_refs(bom_1.bom_ref, bom_2.bom_ref, "<="):
            return False
        if bom_1.purl and not compare_bom_refs(bom_1.purl, bom_2.purl, "<="):
            return False
    else:
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


def eq_allow_new_data_vdr(vdr_1: BomVdr, vdr_2: BomVdr) -> bool:
    """Checks for equivalent values, allowing data not present in original to be present"""
    if vdr_1.id and vdr_1.id != vdr_2.id:
        return False
    if vdr_1.affects and not advanced_eq_lists(vdr_1.affects, vdr_2.affects):
        return False
    # Allows allow_new_versions to be used with allow_new_data
    if vdr_1.options.allow_new_versions:  # type: ignore
        if vdr_1.updated and vdr_1.updated != vdr_2.updated and not compare_date(
                vdr_1.updated, vdr_2.updated, "<="):
            return False
        if vdr_1.bom_ref and vdr_1.bom_ref != vdr_2.bom_ref and not compare_bom_refs(
                vdr_1.bom_ref, vdr_2.bom_ref, "<="):
            return False
        if vdr_1.recommendation and vdr_1.recommendation != vdr_2.recommendation and not compare_recommendations(vdr_1.recommendation, vdr_2.recommendation, "<="):
            return False
    else:
        if vdr_1.bom_ref and vdr_1.bom_ref != vdr_2.bom_ref:
            return False
        if vdr_1.recommendation and vdr_1.recommendation != vdr_2.recommendation:
            return False
        if vdr_1.updated and vdr_1.updated != vdr_2.updated:
            return False
    if vdr_1.advisories and not advanced_eq_lists(vdr_1.advisories, vdr_2.advisories):
        return False
    if vdr_1.analysis and vdr_1.analysis != vdr_2.analysis:
        return False
    if vdr_1.cwes and not advanced_eq_lists(vdr_1.cwes, vdr_2.cwes):
        return False
    if vdr_1.description and vdr_1.description != vdr_2.description:
        return False
    if vdr_1.detail and vdr_1.detail != vdr_2.detail:
        return False
    if vdr_1.properties and not advanced_eq_lists(vdr_1.properties, vdr_2.properties):
        return False
    if vdr_1.published and vdr_1.published != vdr_2.published:
        return False
    if vdr_1.ratings and not advanced_eq_lists(vdr_1.ratings, vdr_2.ratings):
        return False
    if vdr_1.references and not advanced_eq_lists(vdr_1.references, vdr_2.references):
        return False
    return not vdr_1.source or vdr_1.source == vdr_2.source


def check_key(key: str, exclude_keys: Set[str] | List[str]) -> bool:
    return not any(key.startswith(k) for k in exclude_keys)


def compare_vdr_new_versions(vdr_1: BomVdr, vdr_2: BomVdr) -> bool:
    return all((vdr_1.affects == vdr_2.affects,
                compare_recommendations(vdr_1.recommendation, vdr_2.recommendation, "<="),
                (not vdr_1.updated or compare_date(vdr_1.updated, vdr_2.updated, "<=")),
                compare_bom_refs(vdr_1.bom_ref, vdr_2.bom_ref, "<=")))


def create_comp_key(comp: Dict, keys: List[str]) -> str:
    return "|".join([str(comp.get(k, "")) for k in keys])


def create_search_key(key: str, value: str) -> str:
    combined_key = re.sub(r"(?<=\[)[0-9]+(?=])", "", key)
    combined_key += f"|>{value}"
    return combined_key


def get_cdxgen_excludes(includes: List[str], allow_new_versions: bool, allow_new_data: bool) -> Tuple[List[str], List[str], List[str], bool]:

    excludes = {'metadata.timestamp': 'metadata.timestamp', 'serialNumber': 'serialNumber',
                'metadata.tools.components.[].version': 'metadata.tools.components.[].version',
                'metadata.tools.components.[].purl': 'metadata.tools.components.[].purl',
                'metadata.tools.components.[].bom-ref': 'metadata.tools.components.[].bom-ref',
                'properties': 'components.[].properties', 'evidence': 'components.[].evidence',
                'licenses': 'components.[].licenses', 'hashes': 'components.[].hashes',
                'externalReferences': 'components.[].externalReferences',
                'externalreferences': 'components.[].externalReferences'}
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
        options: Options, original_data: Dict, other_data: FlatDicts | None = None,
        components: List | None = None, services: List | None = None,
        dependencies: List | None = None, vulnerabilities: List | None = None
) -> Tuple[FlatDicts, List, List, List, List]:
    if original_data and any((components, services, dependencies, other_data)):
        logger.warning("Both source dict and a list element included. Using source dict.")
    if original_data:
        other_data, components, services, dependencies, vulnerabilities = parse_bom_dict(original_data, options)
    elif not other_data:
        other_data = FlatDicts({})
    for i, value in enumerate(elements := [components, services, dependencies, vulnerabilities]):
        if not value:
            elements[i] = []
    components, services, dependencies, vulnerabilities = elements
    return other_data, components, services, dependencies, vulnerabilities  # type: ignore


def import_csaf(options: "Options", original_data: Dict | None = None, document: FlatDicts | None = None,
                product_tree: FlatDicts | None = None, vex: List | None = None
                ) -> Tuple[FlatDicts, FlatDicts, List]:
    if original_data:
        if document or product_tree or vex:
            logger.warning("Both source dict and parsed elements included. Using source dict.")
        return FlatDicts(original_data.get("document", {})), FlatDicts(
            original_data.get("product_tree", {})), [
            CsafVulnerability(i, options) for i in original_data.get("vulnerabilities", [])]
    return document or FlatDicts({}), product_tree or FlatDicts({}), vex or []


def import_flat_dict(data: Dict | List[FlatElement]) -> List[FlatElement]:
    if not data:
        return []
    if data and isinstance(data, List) and isinstance(data[0], FlatElement):
        return data
    if not isinstance(data, Dict):
        raise TypeError("data must be a dict or list of FlatElement")
    flat_dicts = []
    for key, value in data.items():
        ele = FlatElement(key, value)
        flat_dicts.append(ele)
    return flat_dicts


def order_documents(doc_1: BomDicts | CsafDicts, doc_2: BomDicts | CsafDicts) -> Tuple:
    """Ensures we compare boms in the correct order for allow_new_versions and allow_new_data"""
    if doc_1.options.doc_num == 1:
        return doc_1, doc_2
    return doc_2, doc_1


def parse_bom_dict(original_data: Dict, options: Options) -> Tuple[FlatDicts, List, List, List, List]:
    other_data: Dict = {}
    services: List = []
    dependencies: List = []
    vulnerabilities: List = []
    components: List = []
    if not original_data:
        return FlatDicts(other_data), components, services, dependencies, vulnerabilities
    components = [BomComponent(i, options) for i in original_data.get("components", [])]
    services.extend(BomService(i, options) for i in original_data.get("services", []))
    dependencies.extend(BomDependency(i, options) for i in original_data.get("dependencies", []))
    vulnerabilities.extend(BomVdr(data=i, options=options) for i in original_data.get("vulnerabilities", []))
    for key, value in original_data.items():
        if key not in {"components", "dependencies", "services", "vulnerabilities"}:
            other_data |= {key: value}
    return FlatDicts(other_data), components, services, dependencies, vulnerabilities
