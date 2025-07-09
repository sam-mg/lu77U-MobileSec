#!/usr/bin/env python3
"""
Output Directory Organizer for lu77U-MobileSec

Creates and manages structured output directories for APK analysis results
based on the requested format:

<APK_Name>_<Date>_<Time>/
├── Files Processed for Working/
├── Prompts Given to AI/
├── Response By AI/
├── Fixes Requested/
│   └── <Vulnerability_Name.md>
└── Dynamic Analysis/
    └── <APK_Name>.json (converted to .md if possible)
"""

import os
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Any, Union


class OutputDirectoryOrganizer:
    """Manages structured output directories for APK analysis"""
    
    def __init__(self, base_output_dir: Optional[str] = None):
        """Initialize output organizer"""
        self.base_output_dir = Path(base_output_dir or "Works")
        
    def create_apk_analysis_structure(self, apk_name: str, timestamp: Optional[str] = None) -> Dict[str, Path]:
        """
        Create the main analysis directory structure for an APK
        
        Args:
            apk_name: Name of the APK file (without extension)
            timestamp: Optional timestamp string, if None will generate current
            
        Returns:
            Dict with paths to each subdirectory
        """
        if not timestamp:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Main analysis directory
        analysis_dir_name = f"{apk_name}_{timestamp}"
        main_dir = self.base_output_dir / analysis_dir_name
        
        # Create directory structure
        directories = {
            'main': main_dir,
            'files_processed': main_dir / "Files Processed for Working",
            'prompts_given': main_dir / "Prompts Given to AI",
            'response_by_ai': main_dir / "Response By AI", 
            'fixes_requested': main_dir / "Fixes Requested",
            'dynamic_analysis': main_dir / "Dynamic Analysis"
        }
        
        # Create all directories
        for dir_path in directories.values():
            dir_path.mkdir(parents=True, exist_ok=True)
            
        print(f"📁 Created analysis structure: {main_dir}")
        return directories
    
    def save_processed_file(self, content: str, filename: str, directories: Dict[str, Path]) -> Optional[Path]:
        """Save processed file content"""
        try:
            file_path = directories['files_processed'] / filename
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"📄 Saved processed file: {filename}")
            return file_path
        except Exception as e:
            print(f"❌ Failed to save processed file {filename}: {e}")
            return None
    
    def save_ai_prompt(self, prompt: str, filename: str, directories: Dict[str, Path]) -> Optional[Path]:
        """Save AI prompt to prompts directory"""
        try:
            file_path = directories['prompts_given'] / filename
            
            # Add metadata header
            prompt_content = f"""# AI Prompt
**Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**File**: {filename}

---

{prompt}
"""
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(prompt_content)
            print(f"🤖 Saved AI prompt: {filename}")
            return file_path
        except Exception as e:
            print(f"❌ Failed to save AI prompt {filename}: {e}")
            return None
    
    def save_ai_response(self, response: str, filename: str, directories: Dict[str, Path], 
                        prompt_file: Optional[str] = None) -> Optional[Path]:
        """Save AI response to responses directory"""
        try:
            file_path = directories['response_by_ai'] / filename
            
            # Add metadata header
            response_content = f"""# AI Response
**Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**File**: {filename}
"""
            if prompt_file:
                response_content += f"**Related Prompt**: {prompt_file}\n"
            
            response_content += f"""
---

{response}
"""
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(response_content)
            print(f"🤖 Saved AI response: {filename}")
            return file_path
        except Exception as e:
            print(f"❌ Failed to save AI response {filename}: {e}")
            return None
    
    def save_vulnerability_fix(self, vulnerability: Dict[str, Any], fix_content: str, 
                             directories: Dict[str, Path]) -> Optional[Path]:
        """Save vulnerability fix as markdown file"""
        try:
            # Generate filename from vulnerability name
            vuln_name = vulnerability.get('title', 'Unknown_Vulnerability')
            safe_name = "".join(c for c in vuln_name if c.isalnum() or c in "._- ").replace(" ", "_")
            filename = f"{safe_name}.md"
            
            file_path = directories['fixes_requested'] / filename
            
            # Create comprehensive fix document
            fix_document = f"""# Security Fix: {vulnerability.get('title', 'Unknown')}

## Vulnerability Information
- **Severity**: {vulnerability.get('severity', 'Unknown')}
- **Location**: {vulnerability.get('location', 'Unknown')}
- **File Type**: {vulnerability.get('file_type', 'Unknown')}
- **Pattern**: {vulnerability.get('pattern', 'N/A')}
- **Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Description
{vulnerability.get('description', 'No description available')}

## Impact
{vulnerability.get('impact', 'No impact information available')}

## Matched Text
```
{vulnerability.get('matched_text', 'N/A')}
```

## Recommended Fix

{fix_content}

## Implementation Notes
{vulnerability.get('recommendation', 'No specific recommendations provided')}

## Additional Information
- **Code Context**: {vulnerability.get('code', 'N/A')}
- **Line Number**: {vulnerability.get('line', 'N/A')}
- **Confidence**: {vulnerability.get('confidence', 'N/A')}

---
*Generated by lu77U-MobileSec - APK Security Analysis Tool*
"""
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(fix_document)
            print(f"🔧 Saved vulnerability fix: {filename}")
            return file_path
            
        except Exception as e:
            print(f"❌ Failed to save vulnerability fix: {e}")
            return None
    
    def save_dynamic_analysis(self, analysis_data: Union[Dict, str], apk_name: str, 
                            directories: Dict[str, Path], convert_to_md: bool = True) -> Optional[Path]:
        """Save dynamic analysis results"""
        try:
            if convert_to_md:
                # Convert to markdown format
                filename = f"{apk_name}_dynamic_analysis.md"
                file_path = directories['dynamic_analysis'] / filename
                
                if isinstance(analysis_data, str):
                    # Try to parse as JSON first
                    try:
                        data = json.loads(analysis_data)
                    except:
                        # If not JSON, treat as plain text
                        data = {"analysis_text": analysis_data}
                else:
                    data = analysis_data
                
                # Create markdown content
                md_content = f"""# Dynamic Analysis Report: {apk_name}

**Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Analysis Type**: Dynamic Security Testing

---

"""
                
                if isinstance(data, dict):
                    # Format dictionary data as markdown
                    for key, value in data.items():
                        md_content += f"## {key.replace('_', ' ').title()}\n\n"
                        
                        if isinstance(value, (dict, list)):
                            # Convert complex objects to formatted text
                            if isinstance(value, dict):
                                for sub_key, sub_value in value.items():
                                    md_content += f"- **{sub_key}**: {sub_value}\n"
                            else:  # list
                                for item in value:
                                    if isinstance(item, dict):
                                        md_content += f"- {item}\n"
                                    else:
                                        md_content += f"- {item}\n"
                        else:
                            md_content += f"{value}\n"
                        
                        md_content += "\n"
                else:
                    md_content += f"```\n{data}\n```\n"
                
                md_content += "\n---\n*Generated by lu77U-MobileSec - Dynamic Analysis Component*\n"
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(md_content)
                    
            else:
                # Save as JSON
                filename = f"{apk_name}_dynamic_analysis.json"
                file_path = directories['dynamic_analysis'] / filename
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    if isinstance(analysis_data, str):
                        f.write(analysis_data)
                    else:
                        json.dump(analysis_data, f, indent=2, ensure_ascii=False)
            
            print(f"📊 Saved dynamic analysis: {filename}")
            return file_path
            
        except Exception as e:
            print(f"❌ Failed to save dynamic analysis: {e}")
            return None
    
    def create_analysis_summary(self, directories: Dict[str, Path], apk_name: str, 
                               analysis_stats: Dict[str, Any]) -> Optional[Path]:
        """Create a summary markdown file for the entire analysis"""
        try:
            summary_file = directories['main'] / "ANALYSIS_SUMMARY.md"
            
            summary_content = f"""# APK Security Analysis Summary

## General Information
- **APK Name**: {apk_name}
- **Analysis Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **Analysis Duration**: {analysis_stats.get('duration', 'N/A')}
- **Framework Type**: {analysis_stats.get('framework_type', 'N/A')}

## Analysis Components
- **Static Analysis**: {analysis_stats.get('static_analysis', 'N/A')}
- **Dynamic Analysis**: {analysis_stats.get('dynamic_analysis', 'N/A')}
- **AI Analysis**: {analysis_stats.get('ai_analysis', 'N/A')}

## Results Overview
- **Total Vulnerabilities Found**: {analysis_stats.get('total_vulnerabilities', 0)}
- **High Severity**: {analysis_stats.get('high_severity', 0)}
- **Medium Severity**: {analysis_stats.get('medium_severity', 0)}
- **Low Severity**: {analysis_stats.get('low_severity', 0)}

## Directory Structure
```
{apk_name}_{analysis_stats.get('timestamp', 'timestamp')}/
├── Files Processed for Working/     # {len(list(directories['files_processed'].glob('*'))) if directories['files_processed'].exists() else 0} files
├── Prompts Given to AI/             # {len(list(directories['prompts_given'].glob('*'))) if directories['prompts_given'].exists() else 0} files
├── Response By AI/                  # {len(list(directories['response_by_ai'].glob('*'))) if directories['response_by_ai'].exists() else 0} files
├── Fixes Requested/                 # {len(list(directories['fixes_requested'].glob('*'))) if directories['fixes_requested'].exists() else 0} files
└── Dynamic Analysis/                # {len(list(directories['dynamic_analysis'].glob('*'))) if directories['dynamic_analysis'].exists() else 0} files
```

## Files Generated
"""
            
            # List files in each directory
            for dir_name, dir_path in directories.items():
                if dir_name == 'main':
                    continue
                    
                summary_content += f"\n### {dir_name.replace('_', ' ').title()}\n"
                
                if dir_path.exists():
                    files = list(dir_path.glob('*'))
                    if files:
                        for file in files:
                            if file.is_file():
                                size = file.stat().st_size
                                summary_content += f"- `{file.name}` ({size:,} bytes)\n"
                    else:
                        summary_content += "- *No files generated*\n"
                else:
                    summary_content += "- *Directory not created*\n"
            
            summary_content += f"""

---
*Analysis completed by lu77U-MobileSec v1.0.0*  
*Report generated on {datetime.now().strftime("%Y-%m-%d at %H:%M:%S")}*
"""
            
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write(summary_content)
                
            print(f"📋 Created analysis summary: ANALYSIS_SUMMARY.md")
            return summary_file
            
        except Exception as e:
            print(f"❌ Failed to create analysis summary: {e}")
            return None
    
    def cleanup_empty_directories(self, directories: Dict[str, Path]) -> None:
        """Remove empty directories from the analysis structure"""
        try:
            for dir_name, dir_path in directories.items():
                if dir_name == 'main':
                    continue
                    
                if dir_path.exists() and dir_path.is_dir():
                    # Check if directory is empty
                    if not any(dir_path.iterdir()):
                        dir_path.rmdir()
                        print(f"🗑️  Removed empty directory: {dir_name}")
                        
        except Exception as e:
            print(f"⚠️  Warning: Could not cleanup empty directories: {e}")


# Global instance for easy access
output_organizer = OutputDirectoryOrganizer()


# Convenience functions
def create_apk_analysis_structure(apk_name: str, timestamp: Optional[str] = None) -> Dict[str, Path]:
    """Create APK analysis directory structure"""
    return output_organizer.create_apk_analysis_structure(apk_name, timestamp)


def save_processed_file(content: str, filename: str, directories: Dict[str, Path]) -> Optional[Path]:
    """Save processed file content"""
    return output_organizer.save_processed_file(content, filename, directories)


def save_ai_prompt(prompt: str, filename: str, directories: Dict[str, Path]) -> Optional[Path]:
    """Save AI prompt"""
    return output_organizer.save_ai_prompt(prompt, filename, directories)


def save_ai_response(response: str, filename: str, directories: Dict[str, Path], 
                    prompt_file: Optional[str] = None) -> Optional[Path]:
    """Save AI response"""
    return output_organizer.save_ai_response(response, filename, directories, prompt_file)


def save_vulnerability_fix(vulnerability: Dict[str, Any], fix_content: str, 
                          directories: Dict[str, Path]) -> Optional[Path]:
    """Save vulnerability fix"""
    return output_organizer.save_vulnerability_fix(vulnerability, fix_content, directories)


def save_dynamic_analysis(analysis_data: Union[Dict, str], apk_name: str, 
                         directories: Dict[str, Path], convert_to_md: bool = True) -> Optional[Path]:
    """Save dynamic analysis results"""
    return output_organizer.save_dynamic_analysis(analysis_data, apk_name, directories, convert_to_md)


def create_analysis_summary(directories: Dict[str, Path], apk_name: str, 
                           analysis_stats: Dict[str, Any]) -> Optional[Path]:
    """Create analysis summary"""
    return output_organizer.create_analysis_summary(directories, apk_name, analysis_stats)
