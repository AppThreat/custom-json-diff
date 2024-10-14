import logging
import re
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from json_flatten import unflatten  # type: ignore

from custom_json_diff.lib.utils import (
    compare_bom_refs,
    compare_date,
    compare_recommendations,
    compare_versions,
    import_config,
    split_bom_ref
)


logger = logging.getLogger(__name__)


class Array(list):
    def __init__(self, *args):
        super().__init__(*args)

    def __eq__(self, other):
        return all((all(i in other for i in self), all(i in self for i in other)))


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
    # deprecated
    testing: bool = False
    comp_keys: List = field(default_factory=list)
    svc_keys: List = field(default_factory=list)
    doc_num: int = 1
    include_empty: bool = False

    def __post_init__(self):
        if self.config:
            toml_data = import_config(self.config)
            self.preconfig_type = toml_data.get("preset_settings", {}).get("type", "")
            self.allow_new_versions = toml_data.get("preset_settings", {}).get(
                "allow_new_versions", False)
            self.allow_new_data = toml_data.get("preset_settings", {}).get("allow_new_data", False)
            self.report_template = toml_data.get("preset_settings", {}).get("report_template", "")
            self.sort_keys = toml_data.get("settings", {}).get("sort_keys", [])
            self.exclude = toml_data.get("settings", {}).get("excluded_fields", [])
            self.include = toml_data.get("settings", {}).get("include_extra", [])
            self.include_empty = toml_data.get("settings", {}).get("include_empty", False)
        if self.preconfig_type == "bom":
            tmp_exclude, tmp_bom_key_fields, tmp_service_key_fields, self.do_advanced = (
                get_cdxgen_excludes(self.include, self.allow_new_versions, self.allow_new_data))
            self.comp_keys.extend(tmp_bom_key_fields)
            self.svc_keys.extend(tmp_service_key_fields)
            self.exclude.extend(tmp_exclude)
            self.sort_keys.extend(["purl", "bom-ref", "content", "cve", "id", "url", "text", "ref", "name", "value", "location"])
        elif self.preconfig_type == "csaf":
            self.exclude.extend(["document.tracking"])
            self.sort_keys.extend(["text", "title", "product_id", "url"])
        self.exclude = list(set(self.exclude))
        self.include = list(set(self.include))
        self.comp_keys = list(set(self.comp_keys))
        self.svc_keys = list(set(self.svc_keys))
        self.sort_keys = list(set(self.sort_keys))


class OptionedClass:
    def __init__(self, options: Options):
        self._options = options

    @property
    def options(self):
        return self._options

    @options.setter
    def options(self, value):
        self._options = self._update_options(value)

    def _update_options(self, options):
        self._options = options


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

    def to_dict(self, unflat: bool = False, include_empty: bool = False) -> Dict:
        if include_empty:
            result = {i.key: i.value for i in self.data}
        else:
            result = {i.key: i.value for i in self.data if i.value}
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


class BomComponent(OptionedClass):
    def __init__(self, comp: Dict, options: Options):
        super().__init__(options)
        self.author = comp.get("author", "")
        self.bom_ref = comp.get("bom-ref", "")
        self.component_type = comp.get("type", "")
        self.description = comp.get("description", "")
        self.evidence = comp.get("evidence", {})
        self._external_references = Array(comp.get("externalReferences", []))
        self.group = comp.get("group", "")
        self._hashes = Array(comp.get("hashes", []))
        self._licenses = Array(comp.get("licenses", []))
        self.name = comp.get("name", "")
        self.original_data: Dict = {}  # deprecated
        self._properties = Array(comp.get("properties", []))
        self.publisher = comp.get("publisher", "")
        self.purl = comp.get("purl", "")
        self.scope = comp.get("scope", [])
        self.search_key = ""  # deprecated
        self.version = comp.get("version", "")

    def __eq__(self, other):
        if not self.options.allow_new_data and not self.options.allow_new_versions:
            return all((self.bom_ref == other.bom_ref, self.purl == other.purl, self.version == other.version,
                        self._check_unversioned_eq(other), self._check_list_eq(other)))
        c1, c2 = order_documents(self, other)
        if self.options.allow_new_versions and self.options.allow_new_data:
            return eq_allow_new_data_comp(c1, c2)
        if self.options.allow_new_versions:
            return all((
                compare_versions(c1.version, c2.version, "<="),
                compare_bom_refs(c1.bom_ref, c2.bom_ref, "<="),
                compare_bom_refs(c1.purl, c2.purl, "<="),
                c1._check_unversioned_eq(c2),
                c1._check_list_eq(c2)
            ))
        return eq_allow_new_data_comp(c1, c2)

    def _check_list_eq(self, other):
        return all((self.external_references == other.external_references,
                    self.hashes == other.hashes, self.licenses == other.licenses,
                    self.properties == other.properties))

    def _check_unversioned_eq(self, other):
        return all((self.author == other.author, self.component_type == other.component_type,
                    self.evidence == other.evidence, self.group == other.group,
                    self.name == other.name, self.publisher == other.publisher,
                    self.scope == other.scope))

    @property
    def external_references(self):
        return self._external_references

    @external_references.setter
    def external_references(self, value):
        self._external_references = Array(value)

    @property
    def hashes(self):
        return self._hashes

    @hashes.setter
    def hashes(self, value):
        self._hashes = Array(value)

    @property
    def licenses(self):
        return self._licenses

    @licenses.setter
    def licenses(self, value):
        self._licenses = Array(value)

    @property
    def properties(self):
        return self._properties

    @properties.setter
    def properties(self, value):
        self._properties = Array(value)

    def to_dict(self):
        return {
            "author": self.author, "bom-ref": self.bom_ref, "type": self.component_type,
            "description": self.description, "evidence": self.evidence,
            "externalReferences": self.external_references, "group": self.group,
            "hashes": self.hashes, "licenses": self.licenses, "name": self.name,
            "properties": self.properties, "publisher": self.publisher, "purl": self.purl,
            "scope": self.scope, "version": self.version}


class BomDependency(OptionedClass):
    def __init__(self, dep: Dict, options: "Options"):
        super().__init__(options)
        self._ref = dep.get("ref", "")
        self._deps = Array(dep.get("dependsOn", []))
        self.original_data: Dict = {} # deprecated
        self._ref_no_version, self._deps_no_version = import_bom_dependency(
            dep, options.allow_new_versions) if options.allow_new_versions else "", Array([])

    def __eq__(self, other):
        if not self.options.allow_new_data and not self.options.allow_new_versions:
            return self.ref == other.ref and self.deps == other.deps
        d1, d2 = order_documents(self, other)
        if self.options.allow_new_data and self.options.allow_new_versions:
            return d1._ref_no_version == d2._ref_no_version and advanced_eq_lists(d1._deps_no_version, d2._deps_no_version)
        if self.options.allow_new_data:
            return d1.ref == d2.ref and advanced_eq_lists(d1.deps, d2.deps)
        return self._ref_no_version == other._ref_no_version and self._deps_no_version == other._deps_no_version

    @property
    def deps(self):
        return self._deps

    @deps.setter
    def deps(self, value):
        self._deps = Array(value)
        if self.options.allow_new_versions:
            self._ref_no_version, self._deps_no_version = import_bom_dependency(
                {"ref": self.ref, "dependsOn": self.deps}, True)

    @property
    def ref(self):
        return self._ref

    @ref.setter
    def ref(self, value):
        self._ref = value
        if self.options.allow_new_versions:
            self._ref_no_version, self._deps_no_version = import_bom_dependency(
                {"ref": self.ref, "dependsOn": self.deps}, self.options.allow_new_versions)

    def clear(self):
        options = self.options
        self.__init__(dep={}, options=options)

    def to_dict(self):
        return {"ref": self.ref, "dependsOn": self.deps}


class BomDicts(OptionedClass):
    def __init__(self, options: "Options", filename: str, original_data: Dict, other_data: FlatDicts | None = None,
                 components: List | None = None, services: List | None = None,
                 dependencies: List | None = None, vulnerabilities: List | None = None):
        super().__init__(options)
        self.options.doc_num = 1 if filename == options.file_1 else 2
        self.misc_data, self._components, self._services, self._dependencies, self._vdrs = import_bom_dict(
            options, original_data, other_data, components, services, dependencies, vulnerabilities)
        self.filename = filename

    def __eq__(self, other):
        return (self.misc_data == other.misc_data and self.components == other.components and
                self.services == other.services and self.dependencies == other.dependencies and
                self.vdrs == self.vdrs)

    def __sub__(self, other):
        other_data = self.misc_data - other.misc_data
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

    @property
    def components(self):
        return self._components

    @components.setter
    def components(self, value):
        _, self._components, _, _, _ = import_bom_dict(self.options, {}, components=value)

    @property
    def dependencies(self):
        return self._dependencies

    @dependencies.setter
    def dependencies(self, value):
        _, _, _, self._dependencies, _ = import_bom_dict(self.options, {}, dependencies=value)

    def _update_options(self, value):
        self._options = value
        for i in self._components:
            i.options = value
        for i in self._services:
            i.options = value
        for i in self._dependencies:
            i.options = value
        for i in self._vdrs:
            i.options = value

    @property
    def services(self):
        return self._services

    @services.setter
    def services(self, value):
        _, _, self._services, _, _ = import_bom_dict(self.options, {}, services=value)

    @property
    def vdrs(self):
        return self._vdrs

    @vdrs.setter
    def vdrs(self, value):
        _, _, _, _, self._vdrs = import_bom_dict(self.options, {}, vulnerabilities=value)

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
        other_data = self.misc_data.intersection(other.misc_data)
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

    def to_dict(self) -> Dict:
        return {
            "components": {
            "libraries": [i.to_dict() for i in self.components if
                          i.component_type == "library"],
            "frameworks": [i.to_dict() for i in self.components if
                           i.component_type == "framework"],
            "applications": [i.to_dict() for i in self.components if
                             i.component_type == "application"],
            "other_components": [i.to_dict() for i in self.components if
                                 i.component_type not in ("library", "framework", "application")]},
            "dependencies": [i.to_dict() for i in self.dependencies],
            "services": [i.to_dict() for i in self.services],
            "vulnerabilities": [i.to_dict() for i in self.vdrs],
            "misc_data": self.misc_data.to_dict(unflat=True)
        }

    def to_summary(self) -> Dict:
        return {self.filename: self.to_dict()}


class BomService(OptionedClass):
    def __init__(self, svc: Dict, options: "Options"):
        super().__init__(options)
        self.search_key = create_comp_key(svc, options.svc_keys)
        self.original_data = svc  # deprecated
        self.name = svc.get("name", "")
        self._endpoints = Array(svc.get("endpoints", []))
        self.authenticated = svc.get("authenticated", "")
        self.x_trust_boundary = svc.get("x-trust-boundary", "")

    def __eq__(self, other):
        return self.search_key == other.search_key and self.endpoints == other.endpoints

    @property
    def endpoints(self):
        return self._endpoints

    @endpoints.setter
    def endpoints(self, value):
        self._endpoints = Array(value)

    def to_dict(self):
        return {
            "name": self.name,
            "endpoints": self._endpoints,
            "authenticated": self.authenticated,
            "x-trust-boundary": self.x_trust_boundary
        }


class BomVdr(OptionedClass):
    """Class for holding bom vulnerability data"""
    def __init__(self, data: Optional[Dict] = None, options: "Options" = Options(), **kwargs):
        super().__init__(options)
        if not data:
            data = {}
        self.id = kwargs.get("id") or (data.get("id") or "")
        self.bom_ref = kwargs.get("bom_ref") or (data.get("bom-ref") or "")
        self._advisories = Array(kwargs.get("advisories") or (data.get("advisories") or []))
        self._affects = Array(BomVdrAffects(i, options) for i in (kwargs.get("affects") or (data.get("affects") or [])))
        if self._affects and not isinstance(self.affects[0], BomVdrAffects):
            self._affects = Array([BomVdrAffects(i, self.options) for i in self._affects])
        self.analysis = kwargs.get("analysis") or (data.get("analysis") or {})
        self._cwes = Array(kwargs.get("cwes") or (data.get("cwes") or []))
        self.description = kwargs.get("description") or (data.get("description") or "")
        self.detail = kwargs.get("detail") or (data.get("detail") or "")
        self._properties = Array(kwargs.get("properties") or (data.get("properties") or []))
        self.published = kwargs.get("published") or (data.get("published") or "")
        self._ratings = Array(kwargs.get("ratings") or (data.get("ratings") or []))
        self.recommendation = kwargs.get("recommendation") or (data.get("recommendation") or "")
        self._references = Array(kwargs.get("references") or (data.get("references") or []))
        self.source = kwargs.get("source") or (data.get("source") or {})
        self.updated = kwargs.get("updated") or (data.get("updated") or "")

    def __eq__(self, other):
        if not self.options.allow_new_data and not self.options.allow_new_versions:
            return all((self._field_eq(other), self.bom_ref == other.bom_ref,
                        self.affects == other.affects, self.updated == other.updated))
        b1, b2 = order_documents(self, other)
        if self.options.allow_new_data:
            # eq_allow_new_data_vdr checks for allow_new_versions as well
            return eq_allow_new_data_vdr(b1, b2)
        return self._field_eq(other) and compare_vdr_new_versions(b1, b2)

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

    @property
    def advisories(self):
        return self._advisories

    @advisories.setter
    def advisories(self, value):
        self._advisories = Array(value)

    @property
    def affects(self):
        return self._affects

    @affects.setter
    def affects(self, value):
        if value and not isinstance(value[0], BomVdrAffects):
            value = [BomVdrAffects(i, self.options) for i in value]
        self._affects = Array(value)

    @property
    def cwes(self):
        return self._cwes

    @cwes.setter
    def cwes(self, value):
        self._cwes = Array(value)

    @property
    def properties(self):
        return self._properties

    @properties.setter
    def properties(self, value):
        self._properties = Array(value)

    @property
    def references(self):
        return self._references

    @references.setter
    def references(self, value):
        self._references = Array(value)

    @property
    def ratings(self):
        return self._ratings

    @ratings.setter
    def ratings(self, value):
        self._ratings = Array(value)

    def clear(self):
        options = self.options
        self.__init__(options=options)

    def _update_options(self, value):
        self._options = value
        for i in self._affects:
            i.options = value

    def to_dict(self):
        return {
            "id": self.id,
            "bom-ref": self.bom_ref,
            "advisories": self._advisories,
            "affects": [i.to_dict() for i in self._affects],
            "analysis": self.analysis,
            "cwes": self.cwes,
            "description": self.description,
            "detail": self.detail,
            "properties": self._properties,
            "published": self.published,
            "ratings": self._ratings,
            "recommendation": self.recommendation,
            "references": self._references,
            "source": self.source,
            "updated": self.updated,
        }


class BomVdrAffects(OptionedClass):
    def __init__(self, data: Dict, options: "Options"):
        super().__init__(options)
        self.data = data  # deprecated
        self.ref = data.get("ref", "")
        self._versions = Array(data.get("versions", []))

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

    @property
    def versions(self):
        return self._versions

    @versions.setter
    def versions(self, value):
        self._versions = Array(value)

    def to_dict(self):
        return {"ref": self.ref, "versions": self.versions}


class CsafDicts(OptionedClass):
    def __init__(self, options: "Options", filename: str, original_data: Dict | None = None,
                 document: FlatDicts | None = None, product_tree: FlatDicts | None = None,
                 vulnerabilities: List | None = None):
        super().__init__(options)
        self.document, self.product_tree, self._vulnerabilities = import_csaf(
            options, original_data, document, product_tree, vulnerabilities)
        self.options.doc_num = 1 if filename == options.file_1 else 2
        self.filename = filename

    def __eq__(self, other):
        return all((
            self.document == other.document,
            self.product_tree == other.product_tree,
            self.vulnerabilities == other.vulnerabilities
        ))

    def __sub__(self, other):
        document = self.document - other.document
        product_tree = self.product_tree - other.product_tree
        vulnerabilities = Array([i for i in self.vulnerabilities if i not in other.vulnerabilities])
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

    @property
    def vulnerabilities(self):
        return self._vulnerabilities

    @vulnerabilities.setter
    def vulnerabilities(self, value):
        if value and not isinstance(value[0], CsafVulnerability):
            value = [CsafVulnerability(i, self.options) for i in value]
        self._vulnerabilities = Array(value)

    def _update_options(self, options):
        self._options = options
        for i in self._vulnerabilities:
            i.options = options

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


class CsafScore(OptionedClass):
    def __init__(self, data: Dict, options: "Options"):
        super().__init__(options)
        self.cvss_v3 = data.get("cvss_v3", {})
        self._products = Array(data.get("products", []))

    def __eq__(self, other):
        if not self.options.allow_new_data:
            return self.cvss_v3 == other.cvss_v3 and self.products == other.products
        a, b = order_documents(self, other)
        if a.cvss_v3 and a.cvss_v3 != b.cvss_v3:
            return False
        return all(i in b.products for i in a.products)

    @property
    def products(self):
        return self._products

    @products.setter
    def products(self, value):
        self._products = Array(value)

    def to_dict(self):
        return {
            "cvss_v3": self.cvss_v3,
            "products": self._products
        }


class CsafVulnerability(OptionedClass):
    def __init__(self, data: Dict, options: "Options", **kwargs):
        super().__init__(options)
        self._acknowledgements = Array(data.get("acknowledgements") or kwargs.get("acknowledgements", []))
        self.cve = data.get("cve") or kwargs.get("cve", "")
        self.cwe = data.get("cwe") or kwargs.get("cwe", "")
        self.discovery_date = data.get("discovery_date") or kwargs.get("discovery_date", "")
        self._ids = Array(data.get("ids") or kwargs.get("ids", []))
        self._notes = Array(data.get("notes") or kwargs.get("notes", []))
        self.product_status = data.get("product_status") or kwargs.get("product_status", {})
        self._references = Array(data.get("references") or kwargs.get("references", []))
        self._scores = Array([CsafScore(i, options) for i in (data.get("scores") or kwargs.get("scores", []))])
        self.title = data.get("title") or kwargs.get("title", "")

    def __eq__(self, other):
        if not self.options.allow_new_data:
            return all((
                self.cve == other.cve,
                self.cwe == other.cwe,
                self.discovery_date == other.discovery_date,
                self.product_status == other.product_status,
                self.acknowledgements == other._acknowledgements,
                self.ids == other.ids,
                self.notes == other.notes,
                self.references == other.references,
                self.scores == other.scores,
                self.title == other.title
            ))
        attributes_to_compare = [('cve', lambda a, b: self.cve == other.cve),
            ('cwe', lambda a, b: self.cwe == other.cwe),
            ('discovery_date', lambda a, b: self.discovery_date == other.discovery_date),
            ('product_status', lambda a, b: self.product_status == other.product_status), (
            'acknowledgements',
            lambda a, b: advanced_eq_lists(self.acknowledgements, other.acknowledgements)),
            ('ids', lambda a, b: advanced_eq_lists(self.ids, other.ids)),
            ('notes', lambda a, b: advanced_eq_lists(self.notes, other.notes)), (
            'references',
            lambda a, b: advanced_eq_lists(self.references, other.references)),
            ('scores', lambda a, b: advanced_eq_lists(self.scores, other.scores)),
            ('title', lambda a, b: self.title == other.title),]
        return not any(
            getattr(self, attr) and not compare(self, other)
            for attr, compare in attributes_to_compare
        )

    def _update_options(self, value):
        self._options = value
        for i in self._scores:
            i.options = value

    @property
    def acknowledgements(self):
        return self._acknowledgements

    @acknowledgements.setter
    def acknowledgements(self, value):
        self._acknowledgements = Array(value)

    @property
    def ids(self):
        return self._ids

    @ids.setter
    def ids(self, value):
        self._ids = Array(value)

    @property
    def notes(self):
        return self._notes

    @notes.setter
    def notes(self, value):
        self._notes = Array(value)

    @property
    def references(self):
        return self._references

    @references.setter
    def references(self, value):
        self._references = Array(value)

    @property
    def scores(self):
        return self._scores

    @scores.setter
    def scores(self, value):
        if value and not isinstance(value[0], CsafScore):
            value = [CsafScore(i, self.options) for i in value]
        self._scores = Array(value)

    def clear(self):
        options = self.options
        self.__init__(data={}, options=options)

    def to_dict(self):
        return {
            "acknowledgements": self._acknowledgements,
            "cve": self.cve,
            "cwe": self.cwe,
            "discovery_date": self.discovery_date,
            "ids": self._ids,
            "notes": self._notes,
            "product_status": self.product_status,
            "references": self._references,
            "scores": [i.to_dict() for i in self.scores],
            "title": self.title
        }


def advanced_eq_lists(lst_1: List, lst_2: List) -> bool:
    """Checks that all items in lst_1 are in lst_2 when allow_new_data is True"""
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
        if bom_1.version and not compare_versions(bom_1.version, bom_2.version, "<="):
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
        ref, _ = split_bom_ref(ref)
        new_deps = []
        for dep in deps:
            d, _ = split_bom_ref(dep)
            new_deps.append(d)
        deps = new_deps
    return ref, Array(deps)


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
    return other_data, Array(components), Array(services), Array(dependencies), Array(vulnerabilities)  # type: ignore


def import_csaf(options: "Options", original_data: Dict | None = None, document: FlatDicts | None = None,
                product_tree: FlatDicts | None = None, vex: List | None = None
                ) -> Tuple[FlatDicts, FlatDicts, List]:
    if original_data:
        if document or product_tree or vex:
            logger.warning("Both source dict and parsed elements included. Using source dict.")
        return FlatDicts(original_data.get("document", {})), FlatDicts(
            original_data.get("product_tree", {})), Array([
            CsafVulnerability(i, options) for i in original_data.get("vulnerabilities", [])])
    else:
        if vex:
            if not isinstance(vex[0], CsafVulnerability):
                vex = [CsafVulnerability(i, options) for i in vex]
            vex = Array(vex)
        if document and not isinstance(document, FlatDicts):
            document = FlatDicts(document)  # type: ignore
        if product_tree and not isinstance(product_tree, FlatDicts):
            product_tree = FlatDicts(product_tree)  # type: ignore
    return document or FlatDicts({}), product_tree or FlatDicts({}), vex or Array([])


def import_flat_dict(data: Dict | List[FlatElement]) -> List[FlatElement]:
    if not data:
        return []
    if isinstance(data, List) and isinstance(data[0], FlatElement):
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
    components.extend(BomComponent(i, options) for i in original_data.get("components", []))
    services.extend(BomService(i, options) for i in original_data.get("services", []))
    dependencies.extend(BomDependency(i, options) for i in original_data.get("dependencies", []))
    vulnerabilities.extend(BomVdr(data=i, options=options) for i in original_data.get("vulnerabilities", []))
    for key, value in original_data.items():
        if key not in {"components", "dependencies", "services", "vulnerabilities"}:
            other_data |= {key: value}
    return FlatDicts(other_data), components, services, dependencies, vulnerabilities
