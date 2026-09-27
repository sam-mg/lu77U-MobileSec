#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.java_kotlin_analyzer

Purpose:
    Analyse a conventional Android app: decompile it with JADX, build a graph over the result, and run the rule engine and the AI agent across it.

Responsibilities:
    Check that JADX is configured, decompile, gather the files worth analysing, and orchestrate the analysis phases.

Dependencies:
    The JADX decompiler, the agent package, the rule engine.

Implementation notes:
    This is the default path and the one most scans take, so it is the most developed: it has a real code graph, region fan-out, and a legacy whole-source fallback for providers that cannot drive the tool loop.

Security considerations:
    Decompiles and reads an untrusted APK. Paths cited in findings are resolved within the decompiled tree by the base class, not joined blindly.
"""

import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .agent.profiles import JAVA_KOTLIN
from .base import BaseAnalyzer
from ..ai.provider_factory import get_active_provider
from ..utils.cancellation import ScanCancelled
from ..utils.verbose import plural, verbose_print
from ..utils.response_parser import ResponseParser
from ..utils.xml_utils import filter_strings_xml_file, is_framework_layout_file
from ..utils.display_utils import display_vulnerabilities
from ..utils.output_manager import OutputManager
from lu77U_MobileSec.decompiler.java_kotlin_decompiler import JavaKotlinDecompiler

class JavaKotlinAnalyzer(BaseAnalyzer):
    """
    Purpose:
        Analyses conventional Java and Kotlin Android apps.

    Attributes:
        framework_label: The framework name used in prompts and reports.
        profile: The framework profile selecting prompts and heuristics.
        jadx_output_dir: Where the decompiled source was written.
        apk_base: The APK's filename stem, used for naming.

    Invariants:
        Produces a result in the standard shape whether or not decompilation succeeded.

    Thread-safety:
        One instance per scan; the agent phase fans out internally.
    """
    framework_label = "Java/Kotlin"
    profile = JAVA_KOTLIN

    def __init__(self, verbose=False, progress=None, is_cancelled=None):
        """
        Purpose:
            Construct the analyzer.

        Parameters:
            verbose: Enables tracing and preserves working files.
            progress: Reports phase progress.
            is_cancelled: Polled between phases.

        Postconditions:
            No APK is loaded and no output directory exists yet.
        """
        super().__init__(verbose=verbose, progress=progress, is_cancelled=is_cancelled)

        self.apk_base = None
        self.apk_dir = None
        self.jadx_output_dir = None
        self.results_dir = None
        self.prompts_dir = None
        self.output_manager = OutputManager(verbose=verbose)

        self.java_kotlin_decompiler = JavaKotlinDecompiler(verbose=self.verbose)
        self.response_parser = ResponseParser(verbose=self.verbose)

    def preflight(self) -> Tuple[bool, str]:
        """
        Purpose:
            Check that JADX is configured.

        Returns:
            A readiness flag and, when not ready, the reason.

        Implementation notes:
            JADX is required rather than optional here: without it there is no source to analyse, and this is the path a standard Android app takes.
        """
        from ..tools_checker.jadx_checker import check_jadx_configured
        if not check_jadx_configured(verbose=self.verbose):
            return False, ("JADX is not configured. Set the JADX executable path "
                           "in Settings.")
        return True, ""

    def analyze(self, apk_path: str, defer_cleanup: bool = False) -> dict:
        """
        Purpose:
            Analyse an APK.

        Parameters:
            apk_path: Path to the APK.
            defer_cleanup: Keep the decompiled output for a later phase to read.

        Returns:
            The analysis results.
        """
        return self.analyze_java_kotlin_apk(apk_path, defer_cleanup=defer_cleanup)

    def source_prefixes(self) -> List[str]:
        """
        Purpose:
            Path prefixes to try when resolving a model-cited file.

        Returns:
            The prefixes JADX writes under.

        Implementation notes:
            JADX splits its output into a sources tree and a resources tree, and a model citing a path relative to the package root would otherwise fail to resolve against either.
        """
        return ["sources", "resources"]

    def _count_source_files(self) -> int:
        """
        Purpose:
            Count the decompiled source files, for the report's coverage figures.

        Returns:
            The number of Java and Kotlin files.

        Implementation notes:
            Counted from the tree rather than taken from JADX's own output, which reports classes processed rather than files written and diverges on an app where decompilation partly failed.
        """
        if not self.jadx_output_dir:
            return 0
        import os
        count = 0
        for _dirpath, _dirnames, filenames in os.walk(self.jadx_output_dir):
            count += sum(1 for n in filenames if n.endswith((".java", ".kt")))
        return count

    def decompile_apk(self, apk_path: str) -> bool:
        """
        Purpose:
            Decompile the APK with JADX.

        Parameters:
            apk_path: Path to the APK.

        Returns:
            True when decompilation produced output.

        Side effects:
            Runs JADX, which can take several minutes, and writes the decompiled tree.

        Implementation notes:
            Success is whatever JADX actually wrote, not its exit status -- it exits non-zero on most obfuscated apps while still producing a usable tree.
        """
        jadx_dir = self.output_manager.get_jadx_output_dir()
        result = self.java_kotlin_decompiler.jadx_decompile(apk_path, output_dir=jadx_dir)
        if result:
            self.jadx_output_dir = result
            return True
        return False
    
    def extract_files_for_analysis(self) -> Dict[str, str]:
        """
        Purpose:
            Gather the files worth analysing: the manifest, the developer-written source, the user-defined strings and the app's own layouts.

        Returns:
            The gathered content, grouped by kind.

        Side effects:
            Reads the decompiled tree.

        Implementation notes:
            Framework and generated code is excluded, and resource strings are filtered to the ones a developer wrote. A decompiled app is overwhelmingly library code, and handing that to a model wastes both the budget and its attention. Grouped by kind rather than returned flat, because the prompt treats them differently -- the manifest is context, the source is the subject.
        """
        verbose_print("Extracting files for vulnerability analysis...", self.verbose)
        
        files_content = {
            "android_manifest": "",
            "java_files": {},
            "strings_xml": "",
            "layout_files": {},
            "backup_rules_xml": "",
            "data_extraction_rules_xml": ""
        }
        
        manifest_path = self.jadx_output_dir / "resources" / "AndroidManifest.xml"
        verbose_print(f"Looking for AndroidManifest.xml at: {manifest_path}", self.verbose)
        verbose_print(f"Manifest path exists: {manifest_path.exists()}", self.verbose)
        
        if manifest_path.exists():
            try:
                files_content["android_manifest"] = manifest_path.read_text(encoding='utf-8')
                verbose_print("Extracted AndroidManifest.xml", self.verbose)
            except Exception as e:
                verbose_print(f"Could not read AndroidManifest.xml: {e}", self.verbose)
        else:
            verbose_print("AndroidManifest.xml not found", self.verbose)
        
        layout_dir = self.jadx_output_dir / "resources" / "res" / "layout"
        verbose_print(f"Looking for layout files at: {layout_dir}", self.verbose)
        verbose_print(f"Layout directory exists: {layout_dir.exists()}", self.verbose)
        
        if layout_dir.exists():
            app_layouts_found = 0
            total_layouts_found = 0
            
            for layout_file in layout_dir.glob("*.xml"):
                total_layouts_found += 1
                file_name = layout_file.name
                
                if is_framework_layout_file(file_name, self.verbose):
                    continue
                
                try:
                    content = layout_file.read_text(encoding='utf-8')
                    files_content["layout_files"][file_name] = content
                    app_layouts_found += 1
                    
                    verbose_print(f"Extracted layout: {file_name} ({len(content)} chars)", self.verbose)
                        
                except Exception as e:
                    verbose_print(f"Could not read layout {file_name}: {e}", self.verbose)
            
            verbose_print(f"Extracted {app_layouts_found} app-specific layout files (skipped {total_layouts_found - app_layouts_found} framework layouts)", self.verbose)
        else:
            verbose_print("Layout directory not found", self.verbose)
        
        strings_path = self.jadx_output_dir / "resources" / "res" / "values" / "strings.xml"
        verbose_print(f"Looking for strings.xml at: {strings_path}", self.verbose)
        verbose_print(f"Strings path exists: {strings_path.exists()}", self.verbose)
        
        if strings_path.exists():
            filtered_strings = filter_strings_xml_file(str(strings_path), self.verbose)
            if filtered_strings:
                files_content["strings_xml"] = filtered_strings
                verbose_print("Extracted and filtered strings.xml", self.verbose)
        else:
            verbose_print("strings.xml not found", self.verbose)
        
        backup_rules_path = self.jadx_output_dir / "resources" / "res" / "xml" / "backup_rules.xml"
        if backup_rules_path.exists():
            try:
                files_content["backup_rules_xml"] = backup_rules_path.read_text(encoding='utf-8')
                verbose_print("Extracted backup_rules.xml", self.verbose)
            except Exception as e:
                verbose_print(f"Could not read backup_rules.xml: {e}", self.verbose)
        
        data_extraction_path = self.jadx_output_dir / "resources" / "res" / "xml" / "data_extraction_rules.xml"
        if data_extraction_path.exists():
            try:
                files_content["data_extraction_rules_xml"] = data_extraction_path.read_text(encoding='utf-8')
                verbose_print("Extracted data_extraction_rules.xml", self.verbose)
            except Exception as e:
                verbose_print(f"Could not read data_extraction_rules.xml: {e}", self.verbose)
        
        java_count = 0
        
        verbose_print("Starting Java files extraction", self.verbose)
        
        app_package_dirs = []
        
        verbose_print(f"Looking for sources directories in {self.jadx_output_dir}", self.verbose)
        
        for sources_dir in self.jadx_output_dir.rglob("sources"):
            if sources_dir.is_dir():
                verbose_print(f"Found sources directory: {sources_dir}", self.verbose)
                for item in sources_dir.iterdir():
                    if item.is_dir():
                        package_name = item.name
                        if package_name not in ['androidx', 'android', 'kotlin', 'kotlinx', 'com', 'org']:
                            app_package_dirs.append(item)
                            verbose_print(f"Added app package directory: {item}", self.verbose)
                        elif package_name == 'com':
                            for subitem in item.iterdir():
                                if subitem.is_dir():
                                    subpackage = subitem.name
                                    if subpackage not in ['google', 'android']:
                                        app_package_dirs.append(subitem)
                                        verbose_print(f"Added com.{subpackage} package directory: {subitem}", self.verbose)
                                        for subsubitem in subitem.rglob("*"):
                                            if subsubitem.is_dir():
                                                app_package_dirs.append(subsubitem)
                                    else:
                                        verbose_print(f"Skipped framework package: com.{subpackage}", self.verbose)
                        elif package_name == 'org':
                            for subitem in item.iterdir():
                                if subitem.is_dir():
                                    subpackage = subitem.name
                                    if subpackage not in ['jetbrains', 'intellij', 'apache', 'junit']:
                                        app_package_dirs.append(subitem)
                                        verbose_print(f"Added org.{subpackage} package directory: {subitem}", self.verbose)
                                    else:
                                        verbose_print(f"Skipped framework package: org.{subpackage}", self.verbose)
                        else:
                            verbose_print(f"Skipped framework package: {package_name}", self.verbose)
        
        if not app_package_dirs:
            verbose_print("No app packages found, using fallback to all sources directories", self.verbose)
            for sources_dir in self.jadx_output_dir.rglob("sources"):
                if sources_dir.is_dir():
                    app_package_dirs.append(sources_dir)
        
        verbose_print(f"Found {len(app_package_dirs)} potential app package directories", self.verbose)
        verbose_print(f"Package directories: {[str(d) for d in app_package_dirs]}", self.verbose)
        
        for package_dir in app_package_dirs:
            
            java_files_in_dir = list(package_dir.rglob("*.java"))
            verbose_print(f"Processing {package_dir}, found {len(java_files_in_dir)} .java files", self.verbose)
                
            for java_file in package_dir.rglob("*.java"):
                
                try:
                    rel_path = java_file.relative_to(self.jadx_output_dir)
                    path_str = str(rel_path).lower()
                    
                    if (java_file.name == "R.java" or 
                        any(framework in path_str for framework in [
                            'androidx/', 'android/', 'kotlin/', 'kotlinx/', 
                            'com/google/', 'org/jetbrains/', 'org/intellij/'
                        ])):
                        verbose_print(f"Skipped framework/generated file: {java_file.name}", self.verbose)
                        continue
                    
                    with open(java_file, "r", encoding="utf-8", errors='ignore') as f:
                        content = f.read()
                        
                        class_count = content.count('class ')
                        method_count = content.count('public ') + content.count('private ') + content.count('protected ')
                        
                        if len(content) < 500 and class_count == 0:
                            verbose_print(f"Skipped small/empty Java file: {java_file.name} ({len(content)} chars, {class_count} classes)", self.verbose)
                            continue
                        
                        files_content["java_files"][str(rel_path)] = content
                        java_count += 1
                        verbose_print(f"Added Java file #{java_count}: {rel_path} ({len(content)} chars)", self.verbose)
                        verbose_print(f"Preview: {content}", self.verbose)
                        
                except Exception as e:
                    verbose_print(f"Error reading Java file {java_file}: {e}", self.verbose)
        
        verbose_print("Final extraction summary:", self.verbose)
        manifest_chars = len(files_content['android_manifest']) if files_content['android_manifest'] else 0
        strings_chars = len(files_content['strings_xml']) if files_content['strings_xml'] else 0
        backup_chars = len(files_content['backup_rules_xml']) if files_content['backup_rules_xml'] else 0
        data_extraction_chars = len(files_content['data_extraction_rules_xml']) if files_content['data_extraction_rules_xml'] else 0
        
        verbose_print(f"AndroidManifest.xml: {'Yes (' + str(manifest_chars) + ' chars)' if files_content['android_manifest'] else 'No'}", self.verbose)
        verbose_print(f"strings.xml: {'Yes (' + str(strings_chars) + ' chars)' if files_content['strings_xml'] else 'No'}", self.verbose)
        verbose_print(f"Layout files: {len(files_content['layout_files'])} files", self.verbose)
        if files_content['layout_files']:
            verbose_print("Layout files extracted:", self.verbose)
            for layout_name, layout_content in files_content['layout_files'].items():
                verbose_print(f"- {layout_name} ({len(layout_content)} chars)", self.verbose)
        if backup_chars > 0:
            verbose_print(f"backup_rules.xml: Yes ({backup_chars} chars)", self.verbose)
        if data_extraction_chars > 0:
            verbose_print(f"data_extraction_rules.xml: Yes ({data_extraction_chars} chars)", self.verbose)
        
        alias_map = {
            "android_manifest": "AndroidManifest.xml",
            "strings_xml": "strings.xml",
            "backup_rules_xml": "backup_rules.xml",
            "data_extraction_rules_xml": "data_extraction_rules.xml"
        }
        for key, alias in alias_map.items():
            if files_content.get(key):
                files_content[alias] = files_content[key]

        for layout_name, layout_content in files_content.get("layout_files", {}).items():
            files_content[layout_name] = layout_content
        for java_name, java_content in files_content.get("java_files", {}).items():
            files_content[java_name] = java_content
        
        return files_content

    def analyze_files_for_vulnerabilities(self, files_content: Dict[str, str]) -> List[Dict]:
        """
        Purpose:
            Run the legacy whole-source analysis, for providers that cannot drive the agentic tool loop.

        Parameters:
            files_content: The gathered files.

        Returns:
            The findings.

        Side effects:
            Makes provider requests.

        Implementation notes:
            This is the fallback path. It sends the gathered source in one request rather than letting the model navigate, which works for a small app and systematically under-reports a large one because the source exceeds the context window. Retained because a provider without usable tool-calling would otherwise produce nothing at all.
        """
        verbose_print("Analyzing files for security vulnerabilities...", self.verbose)
            
        if files_content['java_files']:
            verbose_print("Java files selected for analysis:", self.verbose)
            for idx, (file_path, content) in enumerate(files_content['java_files'].items(), 1):
                verbose_print(f"{idx}. {file_path} ({len(content)} chars)", self.verbose)
        
        vulnerabilities = []
        
        from ..config.prompts import VulnerabilityPrompts
        analysis_prompt = VulnerabilityPrompts.get_java_kotlin_analysis_prompt()
        
        if files_content["android_manifest"]:
            analysis_prompt += f"\n\n--- AndroidManifest.xml ---\n{files_content['android_manifest']}"
        
        if files_content.get("strings_xml"):
            analysis_prompt += f"\n\n--- strings.xml ---\n{files_content['strings_xml']}"
        
        if files_content.get("layout_files"):
            for layout_name, layout_content in files_content["layout_files"].items():
                analysis_prompt += f"\n\n--- {layout_name} ---\n{layout_content}"
        
        if files_content.get("backup_rules_xml"):
            analysis_prompt += f"\n\n--- backup_rules.xml ---\n{files_content['backup_rules_xml']}"
        
        if files_content.get("data_extraction_rules_xml"):
            analysis_prompt += f"\n\n--- data_extraction_rules.xml ---\n{files_content['data_extraction_rules_xml']}"
        
        for file_path, content in files_content["java_files"].items():
            analysis_prompt += f"\n\n--- {file_path} ---\n{content}"
        
        analysis_prompt += "\n\nANALYZE THE ANDROID CODE ABOVE AND RETURN VULNERABILITIES AS JSON ARRAY ONLY."
        
        verbose_print("Prompt construction complete:", self.verbose)
        verbose_print(f"Prompt length: {len(analysis_prompt)} characters", self.verbose)
        
        estimated_tokens = len(analysis_prompt) // 4
        verbose_print(f"Estimated tokens: ~{estimated_tokens:,}", self.verbose)

        unavailable = getattr(self.ai_provider, "unavailable", None)
        if unavailable:
            verbose_print(
                f"AI provider unavailable ({unavailable}); skipping the non-agentic "
                "fallback analysis", self.verbose)
            return []

        try:
            verbose_print(f"Sending request to active provider ({self.ai_provider.name})...", self.verbose)
            ai_response_dict = self.ai_provider.analyze(analysis_prompt)

            verbose_print("Provider response received", self.verbose)
            verbose_print(f"Provider returned type: {type(ai_response_dict)}", self.verbose)
            
            if isinstance(ai_response_dict, dict):
                verbose_print(f"Response dict has keys: {ai_response_dict.keys()}", self.verbose)
                if 'error' in ai_response_dict:
                    verbose_print(f"Provider returned error: {ai_response_dict['error']}", self.verbose)
                    ai_response = None
                else:
                    ai_response = ai_response_dict.get('response')
                    if ai_response:
                        verbose_print(f"Extracted response length: {len(str(ai_response))} characters", self.verbose)
            else:
                ai_response = ai_response_dict
                        
            if ai_response:
                verbose_print("Parsing AI response", self.verbose)
                verbose_print(f"Calling response parser with type: {type(ai_response)}", self.verbose)
                parsed_vulnerabilities = self.response_parser.parse_json_response(ai_response)
                
                for v in parsed_vulnerabilities:
                    if 'title' in v and 'vulnerability_type' not in v:
                        v['vulnerability_type'] = v['title']
                        verbose_print(f"Normalized 'title' to 'vulnerability_type': {v['title']}", self.verbose)
                
                verbose_print(f"Parsed {len(parsed_vulnerabilities)} vulnerabilities from AI response", self.verbose)
                
                vulnerabilities.extend(parsed_vulnerabilities)
            else:
                verbose_print("No response received from AI", self.verbose)
                if isinstance(ai_response_dict, dict) and 'error' in ai_response_dict:
                    error_msg = ai_response_dict['error']
                    print(f"AI provider error: {error_msg}")
                    verbose_print(f"Full error details: {error_msg}", self.verbose)
                
        except Exception as e:
            print(f"AI analysis failed: {e}")
            verbose_print(f"Exception details: {e}", self.verbose)
            if self.verbose:
                import traceback
                verbose_print(f"Full traceback:", self.verbose)
                traceback.print_exc()
        
        return vulnerabilities


    def analyze_java_kotlin_apk(self, apk_path: str, defer_cleanup: bool = False) -> dict:
        """
        Purpose:
            Run the full Java and Kotlin analysis: decompile, build the graph, run the rule engine and the agent, and merge the results.

        Parameters:
            apk_path: Path to the APK.
            defer_cleanup: Keep the decompiled output for a later phase to read.

        Returns:
            The analysis results.

        Side effects:
            Decompiles the APK, makes provider requests, and removes working files unless deferred.

        Implementation notes:
            The APK-level analysis that feeds the code graph is started in the background while JADX is still running, since the two read different things and the graph work would otherwise be pure added latency on an already slow stage. The rule engine and the agent run over the same decompiled tree and their findings are merged, which is what makes cross-engine agreement available as a confidence signal downstream. Cleanup is deferrable because dynamic verification reads the same sources afterwards.
        """
        verbose_print("Starting Java/Kotlin APK Analysis...", self.verbose)
        
        output_dir = self.output_manager.create_output_directory(apk_path)
        
        if not self.apk_base or not self.apk_dir:
            apk_path_obj = Path(apk_path)
            self.apk_base = apk_path_obj.stem
            self.apk_dir = Path("analysis_output") / self.apk_base
            self.apk_parent_dir = apk_path_obj.parent
        
        verbose_print("Initializing active AI provider with output directory", self.verbose)
        self.ai_provider = get_active_provider(
            verbose=self.verbose,
            output_manager=self.output_manager if self.verbose else None,
            apk_name=self.apk_base
        )
        
        cp = getattr(self, "checkpoint", None)

        try:
            analysis_start_time = time.time()

            from .agent.code_graph import analyze_apk_for_code_graph
            preloaded_apk: Dict[str, Any] = {}

            def _prefetch_apk_analysis():
                """
                Purpose:
                    Compute the APK-level analysis the code graph needs, on a background thread.

                Side effects:
                    Parses the APK and stores the result for the caller.

                Implementation notes:
                    Runs concurrently with JADX because the two are independent -- one reads the archive's bytecode, the other writes source -- and doing them in sequence would add minutes to every scan of a large app.
                """
                preloaded_apk["result"] = analyze_apk_for_code_graph(apk_path, self.verbose)

            apk_prefetch_thread = threading.Thread(
                target=_prefetch_apk_analysis, name="androguard-prefetch", daemon=True)
            apk_prefetch_thread.start()

            resumed_decompile = False
            if cp is not None and cp.reached("decompiled"):
                prior = cp.get("jadx_output_dir")
                if prior and Path(prior).is_dir():
                    self.jadx_output_dir = Path(prior)
                    resumed_decompile = True
                    self.progress("decompiling", 58, "Reusing the decompiled sources from before the interruption")
                    verbose_print(f"Resume: skipping JADX, reusing {prior}", self.verbose)

            if not resumed_decompile:
                self.progress("decompiling", 45, "Running JADX decompiler…")
                verbose_print("Decompiling APK...", self.verbose)
                if not self.decompile_apk(apk_path):
                    verbose_print("JADX decompilation failed - cannot continue analysis", self.verbose)
                    return False
                self.progress("decompiling", 58, "JADX decompilation complete")
                if cp is not None:
                    cp.mark("decompiled", jadx_output_dir=str(self.jadx_output_dir))

            sast_vulns: List[Dict] = []
            leads = []
            from .agent.leads import leads_from_findings
            if cp is not None and cp.reached("sast_done"):
                sast_vulns = list(cp.get("sast_vulns", []) or [])
                leads = leads_from_findings(sast_vulns)
                self.progress("sast", 60, "Reusing deterministic scanner findings from before the interruption")
                verbose_print(f"Resume: skipping scanners, reusing {plural(len(sast_vulns), 'finding')}", self.verbose)
            else:
                self.progress("sast", 60, "Running deterministic scanners…")
                try:
                    sast_vulns = self.run_sast(self.jadx_output_dir, apk_path=apk_path)
                    leads = leads_from_findings(sast_vulns)
                    if leads:
                        verbose_print(
                            f"SAST-first: {plural(len(leads), 'lead')} handed to the "
                            "agent as a worklist", self.verbose)
                except ScanCancelled:
                    raise
                except Exception as e:
                    verbose_print(f"Deterministic scanners failed ({e}); no leads for the agent", self.verbose)
                if cp is not None:
                    cp.mark("sast_done", sast_vulns=sast_vulns)

            vulnerabilities = None
            files_analyzed = 0
            static_transcript = ""
            code_graph = None
            try:
                from .agent.code_graph import build_code_graph
                self.progress("agentic_start", 62, "Agentic process beginning - AI is navigating the decompiled source…")

                apk_prefetch_thread.join()
                code_graph = build_code_graph(
                    apk_path, jadx_output_dir=self.jadx_output_dir, verbose=self.verbose,
                    preloaded=preloaded_apk.get("result"), leads=leads)
                if code_graph is not None:
                    self.progress("agentic_start", 64,
                                  f"Code map built - {plural(len(code_graph.nodes), 'app class', 'app classes')}")

                if cp is not None and cp.reached("agents_done"):
                    vulnerabilities = list(cp.get("agents_vulns", []) or [])
                    files_analyzed = int(cp.get("agents_files_analyzed", 0) or 0)
                    static_transcript = str(cp.get("agents_transcript", "") or "")
                    self.progress("agentic_done", 82,
                                  f"Reusing {plural(len(vulnerabilities), 'finding')} from before the interruption")
                    verbose_print(
                        f"Resume: skipping the agent phase, reusing "
                        f"{plural(len(vulnerabilities), 'finding')}", self.verbose)
                else:
                    verbose_print("Running agentic (tool-using) analysis...", self.verbose)
                    agent_kwargs = dict(
                        framework_label="Java/Kotlin (native Android)", leads=leads)
                    if cp is not None:
                        agent_kwargs["checkpoint"] = cp
                    agent_vulns, completed_ok, transcript = self.run_agent(
                        self.jadx_output_dir, code_graph, **agent_kwargs)
                    if completed_ok:
                        vulnerabilities = agent_vulns
                        files_analyzed = self._count_source_files()
                        static_transcript = transcript
                        verbose_print(f"Agentic analysis produced {plural(len(agent_vulns), 'finding')}", self.verbose)
                        self.progress("agentic_done", 82, f"Agentic process completed - {plural(len(agent_vulns), 'finding')}")
                        if cp is not None:
                            cp.mark("agents_done", agents_vulns=vulnerabilities,
                                   agents_files_analyzed=files_analyzed,
                                   agents_transcript=static_transcript)
                    else:
                        verbose_print("Agentic loop unsupported by provider; using full-dump fallback", self.verbose)
            except ScanCancelled:
                raise
            except Exception as e:
                verbose_print(f"Agentic analysis error: {e}; using full-dump fallback", self.verbose)

            if vulnerabilities is None:
                self.progress("agentic_start", 64, "Falling back to full-dump analysis…")
                files_content = self.extract_files_for_analysis()
                if not files_content["java_files"]:
                    verbose_print("No Java files found - cannot perform vulnerability analysis", self.verbose)
                    return False
                vulnerabilities = self.analyze_files_for_vulnerabilities(files_content)
                files_analyzed = len(files_content.get('java_files', {}))
                self.progress("agentic_done", 82, f"Analysis completed - {plural(len(vulnerabilities), 'finding')}")

            self.progress("agentic_done", 84, "Merging deterministic scanner findings…")
            vulnerabilities = self.merge_findings(vulnerabilities, sast_vulns)

            analysis_time = time.time() - analysis_start_time

            if vulnerabilities:
                self.enrich_vulnerabilities(vulnerabilities, self.jadx_output_dir)
                display_vulnerabilities(vulnerabilities, self.verbose)
            else:
                verbose_print("No vulnerabilities found!", self.verbose)

            verbose_print(f"Total time taken: {analysis_time:.2f} seconds", self.verbose)

            if not self.verbose and not defer_cleanup:
                cleanup_dirs = []

                if self.jadx_output_dir and self.jadx_output_dir.exists():
                    cleanup_dirs.append(self.jadx_output_dir)

                if self.apk_dir and self.apk_dir.exists():
                    cleanup_dirs.append(self.apk_dir)

                for cleanup_dir in cleanup_dirs:
                    try:
                        import shutil
                        shutil.rmtree(cleanup_dir)
                        verbose_print(f"Cleaned up directory: {cleanup_dir}", self.verbose)
                    except Exception as cleanup_error:
                        verbose_print(f"Warning: Could not clean up directory {cleanup_dir}: {cleanup_error}", self.verbose)

            return {
                'success': True,
                'vulnerabilities': vulnerabilities or [],
                'analysis_time': analysis_time,
                'files_analyzed': files_analyzed,
                'framework': 'Java/Kotlin',
                'output_manager': self.output_manager,
                'jadx_output_dir': self.jadx_output_dir,
                'source_root': self.jadx_output_dir,
                'static_transcript': static_transcript,
                'code_graph': code_graph,
                'agent_coverage': getattr(self, 'agent_coverage', {}),
            }
        except ScanCancelled:
            raise
        except Exception as e:
            verbose_print(f"Java/Kotlin analysis failed: {e}", self.verbose)
            verbose_print(f"Exception details: {e}", self.verbose)
            
            if not self.verbose:
                cleanup_dirs = []
                
                if self.jadx_output_dir and self.jadx_output_dir.exists():
                    cleanup_dirs.append(self.jadx_output_dir)
                
                if self.apk_dir and self.apk_dir.exists():
                    cleanup_dirs.append(self.apk_dir)
                
                for cleanup_dir in cleanup_dirs:
                    try:
                        import shutil
                        shutil.rmtree(cleanup_dir)
                        verbose_print(f"Cleaned up directory after error: {cleanup_dir}", self.verbose)
                    except Exception as cleanup_error:
                        verbose_print(f"Warning: Could not clean up directory {cleanup_dir}: {cleanup_error}", self.verbose)
            
            return {
                'success': False,
                'vulnerabilities': [],
                'analysis_time': 0,
                'files_analyzed': 0,
                'framework': 'Java/Kotlin',
                'error': str(e)
            }
