"""Java/Kotlin APK Analysis Module for lu77U-MobileSec"""

import re
import time
from pathlib import Path
from typing import Dict, List, Optional

from ..ai.provider_factory import get_active_provider
from ..utils.cancellation import ScanCancelled
from ..utils.verbose import verbose_print
from ..utils.response_parser import ResponseParser
from ..utils.xml_utils import filter_strings_xml_file, is_framework_layout_file
from ..utils.display_utils import display_vulnerabilities
from ..utils.output_manager import OutputManager
from ..report_generator.syntax_highlight import highlight_lines
from lu77U_MobileSec.decompiler.java_kotlin_decompiler import JavaKotlinDecompiler

CONTEXT_PADDING_LINES = 4

class JavaKotlinAnalyzer:
    
    def __init__(self, verbose=False, progress=None):
        """Initialize Java/Kotlin analyzer.

        ``progress`` is an optional ``(phase, percent, message) -> None`` callback
        used by the web job runner to surface fine-grained phase events (decompile
        vs. agentic analysis) beyond the coarse phases AnalysisService emits.
        """
        self.verbose = verbose
        self._progress = progress or (lambda *a, **kw: None)

        self.apk_base = None
        self.apk_dir = None
        self.jadx_output_dir = None
        self.results_dir = None
        self.prompts_dir = None
        self.output_manager = OutputManager(verbose=verbose)

        self.java_kotlin_decompiler = JavaKotlinDecompiler(verbose=self.verbose)
        self.ai_provider = None
        self.response_parser = ResponseParser(verbose=self.verbose)

    def progress(self, phase: str, percent: int, message: str = "") -> None:
        try:
            self._progress(phase, percent, message)
        except ScanCancelled:
            raise
        except Exception:
            pass

    def _count_source_files(self) -> int:
        """Count decompiled .java/.kt files (for report stats in the agentic path)."""
        if not self.jadx_output_dir:
            return 0
        import os
        count = 0
        for _dirpath, _dirnames, filenames in os.walk(self.jadx_output_dir):
            count += sum(1 for n in filenames if n.endswith((".java", ".kt")))
        return count

    def _resolve_source_path(self, file_rel: str) -> Optional[Path]:
        """Best-effort resolution of an AI-reported ``file`` value to a real
        path inside the (still on-disk, pre-cleanup) JADX output tree. The
        model is never given a strict path contract, so this tries the
        common shapes before falling back to a basename search."""
        if not file_rel or not self.jadx_output_dir:
            return None
        file_rel = file_rel.strip().lstrip('/')
        for candidate in (
            self.jadx_output_dir / file_rel,
            self.jadx_output_dir / "sources" / file_rel,
            self.jadx_output_dir / "resources" / file_rel,
        ):
            if candidate.is_file():
                return candidate
        basename = Path(file_rel).name
        if not basename:
            return None
        try:
            return next(self.jadx_output_dir.rglob(basename), None)
        except Exception:
            return None

    @staticmethod
    def _anchor_line(snippet_lines: List[str]) -> Optional[str]:
        """Pick a snippet line specific enough to locate reliably in the
        source file (skips bare braces and other near-universal lines)."""
        for line in snippet_lines:
            stripped = line.strip()
            if len(stripped) >= 6 and stripped not in ('{', '}', '};', '});'):
                return stripped
        return snippet_lines[0].strip() if snippet_lines else None

    def _locate_snippet_span(self, source_lines: List[str], code_snippet: str) -> Optional[tuple]:
        """Fallback locator when no usable line number was provided: find the
        AI's ``code_snippet`` in the source by its most specific line. Returns
        a 1-based inclusive ``(start, end)`` span, or ``None``."""
        snippet_lines = [l for l in code_snippet.splitlines() if l.strip()]
        anchor = self._anchor_line(snippet_lines)
        if not anchor:
            return None
        for idx, line in enumerate(source_lines):
            if anchor in line:
                start = idx + 1
                end = min(len(source_lines), start + max(1, len(snippet_lines)) - 1)
                return (start, end)
        return None

    def _build_code_context(self, source_lines: List[str], start: int, end: int, filename: str) -> Dict:
        """Build the ``code_context`` block for a 1-based inclusive span
        ``(start, end)``: ±``CONTEXT_PADDING_LINES`` of real source, the raw
        lines, per-line syntax-highlighted HTML (so the website can colorize
        without running Pygments), and the vulnerable span text as ``snippet``."""
        n = len(source_lines)
        start = max(1, min(start, n))
        end = max(start, min(end, n))
        ctx_start = max(1, start - CONTEXT_PADDING_LINES)
        ctx_end = min(n, end + CONTEXT_PADDING_LINES)
        window = source_lines[ctx_start - 1:ctx_end]
        return {
            'start_line': ctx_start,
            'end_line': ctx_end,
            'highlight_start': start,
            'highlight_end': end,
            'lines': window,
            'lines_html': highlight_lines(window, filename),
            'snippet': "\n".join(source_lines[start - 1:end]),
        }

    def _enrich_vulnerabilities_with_context(self, vulnerabilities: List[Dict]) -> None:
        """Attach a ``code_context`` block (±``CONTEXT_PADDING_LINES`` real
        source lines around the vulnerable span, with syntax-highlighted HTML)
        to each finding, while the decompiled tree is still on disk — it's
        deleted right after this runs.

        Primary path uses the AI-cited line span (``line_number``/``line_end``)
        to read the exact source; the AI no longer needs to echo code. A
        finding is left untouched if its file can't be resolved or no line can
        be determined, so reports degrade gracefully."""
        for vuln in vulnerabilities:
            try:
                file_rel = vuln.get('file', '')
                if not file_rel:
                    continue
                source_path = self._resolve_source_path(file_rel)
                if not source_path:
                    continue
                source_lines = source_path.read_text(encoding='utf-8', errors='ignore').splitlines()
                if not source_lines:
                    continue

                start = int(vuln.get('line_number') or 0)
                end = int(vuln.get('line_end') or 0) or start

                if start <= 0:
                    span = self._locate_snippet_span(source_lines, vuln.get('code_snippet', ''))
                    if span is None:
                        continue
                    start, end = span

                if end < start:
                    start, end = end, start

                context = self._build_code_context(source_lines, start, end, source_path.name)
                vuln['code_snippet'] = context.pop('snippet')
                vuln['code_context'] = context
                verbose_print(
                    f"Attached code context for '{vuln.get('vulnerability_type', vuln.get('title', 'finding'))}': "
                    f"{source_path.name} lines {context['start_line']}-{context['end_line']} "
                    f"(highlight {context['highlight_start']}-{context['highlight_end']})", self.verbose)
            except Exception as e:
                verbose_print(f"Could not enrich vulnerability with source context: {e}", self.verbose)

    def decompile_apk(self, apk_path: str) -> bool:
        """Decompile APK using JADX wrapper"""
        # Use the output manager's JADX directory
        jadx_dir = self.output_manager.get_jadx_output_dir()
        result = self.java_kotlin_decompiler.jadx_decompile(apk_path, output_dir=jadx_dir)
        if result:
            self.jadx_output_dir = result
            return True
        return False
    
    def extract_files_for_analysis(self) -> Dict[str, str]:
        """Extract specific Android files for vulnerability analysis (Java, XML, Manifest)"""
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
        """AI ANALYSIS: Analyze extracted files for vulnerabilities using AI"""
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
        """Main function to analyze Java/Kotlin APK.

        ``defer_cleanup`` keeps the decompiled JADX tree on disk after a
        successful analysis instead of deleting it — set this when a dynamic-
        verification phase will follow and needs to read the same sources. The
        caller is then responsible for deleting ``jadx_output_dir`` (returned in
        the result dict) once it's done with it.
        """
        verbose_print("Starting Java/Kotlin APK Analysis...", self.verbose)
        
        # Create output directory structure
        output_dir = self.output_manager.create_output_directory(apk_path)
        
        if not self.apk_base or not self.apk_dir:
            apk_path_obj = Path(apk_path)
            self.apk_base = apk_path_obj.stem
            self.apk_dir = Path("analysis_output") / self.apk_base
            # Get the directory where the APK is located for saving logs
            self.apk_parent_dir = apk_path_obj.parent
        
        verbose_print("Initializing active AI provider with output directory", self.verbose)
        self.ai_provider = get_active_provider(
            verbose=self.verbose,
            output_manager=self.output_manager if self.verbose else None,
            apk_name=self.apk_base
        )
        
        try:
            analysis_start_time = time.time()
            
            self.progress("decompiling", 45, "Running JADX decompiler…")
            verbose_print("Decompiling APK...", self.verbose)
            if not self.decompile_apk(apk_path):
                verbose_print("JADX decompilation failed - cannot continue analysis", self.verbose)
                return False
            self.progress("decompiling", 58, "JADX decompilation complete")

            # Default: agentic, tool-using analysis that navigates the JADX tree
            # itself instead of flattening every file into one prompt. Falls back
            # to the legacy full-dump if the provider can't drive the loop.
            vulnerabilities = None
            files_analyzed = 0
            static_transcript = ""
            code_graph = None
            try:
                from .agent.agent_loop import run_agent_analysis
                from .agent.code_graph import build_code_graph
                self.progress("agentic_start", 62, "Agentic process beginning — AI is navigating the decompiled source…")

                # Build a security-annotated code map from the APK (androguard,
                # already a dependency) so the model gets a real map of the app's
                # own classes — their roles, sink APIs, and hardcoded strings —
                # instead of a flat file tree it navigates poorly. Best-effort:
                # None on any failure → the loop falls back to the file tree.
                code_graph = build_code_graph(
                    apk_path, jadx_output_dir=self.jadx_output_dir, verbose=self.verbose)
                if code_graph is not None:
                    self.progress("agentic_start", 64,
                                  f"Code map built — {len(code_graph.nodes)} app class(es)")

                verbose_print("Running agentic (tool-using) analysis...", self.verbose)
                agent_vulns, completed_ok, transcript = run_agent_analysis(
                    self.ai_provider,
                    self.jadx_output_dir,
                    {"framework": "Java/Kotlin (native Android)"},
                    code_graph=code_graph,
                    verbose=self.verbose,
                )
                if completed_ok:
                    vulnerabilities = agent_vulns
                    files_analyzed = self._count_source_files()
                    static_transcript = transcript
                    verbose_print(f"Agentic analysis produced {len(agent_vulns)} finding(s)", self.verbose)
                    self.progress("agentic_done", 82, f"Agentic process completed — {len(agent_vulns)} finding(s)")
                else:
                    verbose_print("Agentic loop unsupported by provider; using full-dump fallback", self.verbose)
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
                self.progress("agentic_done", 82, f"Analysis completed — {len(vulnerabilities)} finding(s)")

            analysis_time = time.time() - analysis_start_time
            
            if vulnerabilities:
                self._enrich_vulnerabilities_with_context(vulnerabilities)
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
                'static_transcript': static_transcript,
                'code_graph': code_graph,
            }
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