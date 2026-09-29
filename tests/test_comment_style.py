#!/usr/bin/env python3
"""
Module: test_comment_style

Purpose:
    The commenting-standard checker, and that the code shipped here satisfies it.

Responsibilities:
    Pin each rule against a file crafted to break exactly that rule, pin the rules that must not fire on legitimate code, and run the checker over the real package and over the checker itself.

Dependencies:
    pytest, the standard library, and the checker script, imported by path.

Implementation notes:
    Two kinds of test live here. The first pins each rule against a crafted file, so a rule that quietly stops firing is caught rather than passing everything it is given. The second runs the checker over the real package and over the checker itself, which is what the push hook does, so a failure here means a push is meant to fail too.
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = REPO_ROOT / "scripts" / "check_comment_style.py"
PACKAGE_ROOT = REPO_ROOT / "lu77U_MobileSec"


def _load_checker():
    """
    Purpose:
        Import the checker from its path.

    Returns:
        The imported checker module.

    Implementation notes:
        Imported by path because the scripts directory is not an installed package, and making it one would put a developer tool into what gets published.
    """
    spec = importlib.util.spec_from_file_location("check_comment_style", CHECKER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = _load_checker()


CLEAN = '''#!/usr/bin/env python3
"""
Module: sample

Purpose:
    A module that satisfies every rule, used as the baseline the rule tests mutate.
"""


def add(left, right):
    """
    Purpose:
        Add two numbers.

    Parameters:
        left: The first number.
        right: The second number.

    Returns:
        Their sum.
    """
    return left + right
'''


def write(tmp_path, source, name="sample.py"):
    """
    Purpose:
        Write a source file into the temporary directory.

    Parameters:
        tmp_path: The directory to write into.
        source: The file's contents.
        name: The file's name.

    Returns:
        The path written to.
    """
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return path


def rules_for(path):
    """
    Purpose:
        Check one file and collect the names of the rules it broke.

    Parameters:
        path: The file to check.

    Returns:
        The set of rule names reported.

    Implementation notes:
        The names rather than the messages, so a test pins which rule fired without being rewritten every time its wording changes.
    """
    return {v.rule for v in checker.check_path(path)}


class TestCleanBaseline:
    """
    Purpose:
        The baseline file every rule test mutates, and the module names expected of files inside a package.
    """
    def test_the_baseline_file_passes(self, tmp_path):
        """
        Purpose:
            Pin that the baseline breaks no rule at all.

        Parameters:
            tmp_path: Directory the file is written into.

        Implementation notes:
            Every other test in this module mutates this file, so a baseline that already broke something would make each of them pass for the wrong reason.
        """
        path = write(tmp_path, CLEAN)
        assert checker.check_path(path) == []

    def test_a_package_initialiser_is_named_for_its_package(self, tmp_path):
        """
        Purpose:
            Pin that a package initialiser is expected to name the package rather than the file.

        Parameters:
            tmp_path: Directory the package is created in.
        """
        pkg = tmp_path / "mypkg"
        pkg.mkdir()
        source = CLEAN.replace("Module: sample", "Module: mypkg")
        init = pkg / "__init__.py"
        init.write_text(source, encoding="utf-8")
        assert checker.expected_module_name(init) == "mypkg"
        assert checker.check_path(init) == []

    def test_a_nested_module_gets_its_dotted_name(self, tmp_path):
        """
        Purpose:
            Pin that a module inside nested packages is expected to carry the full dotted name, and that a file naming only its own basename is caught.

        Parameters:
            tmp_path: Directory the packages are created in.
        """
        pkg = tmp_path / "mypkg"
        (pkg / "sub").mkdir(parents=True)
        for marker in (pkg / "__init__.py", pkg / "sub" / "__init__.py"):
            marker.write_text(CLEAN.replace("Module: sample", "Module: x"), encoding="utf-8")
        leaf = pkg / "sub" / "leaf.py"
        leaf.write_text(CLEAN, encoding="utf-8")
        assert checker.expected_module_name(leaf) == "mypkg.sub.leaf"
        assert "module-name" in rules_for(leaf)


class TestFileLevelRules:
    """
    Purpose:
        The rules about the file as a whole rather than about any one docstring.
    """
    def test_missing_shebang_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that a file with no interpreter line is caught.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        path = write(tmp_path, CLEAN.split("\n", 1)[1])
        assert "shebang" in rules_for(path)

    def test_wrong_shebang_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that an interpreter line naming a different interpreter is caught.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        bad = CLEAN.replace("#!/usr/bin/env python3", "#!/usr/bin/python")
        path = write(tmp_path, bad)
        assert "shebang" in rules_for(path)

    def test_a_second_shebang_line_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that a second interpreter line further down the file is caught.

        Parameters:
            tmp_path: Directory the file is written into.

        Implementation notes:
            A second one is what a careless merge or a copied file header leaves behind, and it does nothing except look like the first one.
        """
        bad = CLEAN.replace("def add(", "#!/usr/bin/env python3\ndef add(")
        path = write(tmp_path, bad)
        assert "shebang" in rules_for(path)

    def test_a_hash_comment_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that an ordinary comment anywhere in the file is caught.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        bad = CLEAN.replace("    return left + right",
                            "    # add them\n    return left + right")
        path = write(tmp_path, bad)
        assert "hash-comment" in rules_for(path)

    def test_a_shebang_constant_is_not_mistaken_for_a_second_shebang(self, tmp_path):
        """
        Purpose:
            Pin that the interpreter line held inside a string is not read as a second one.

        Parameters:
            tmp_path: Directory the file is written into.

        Implementation notes:
            The checker itself holds that text in a constant, so a rule that matched it anywhere in the file would report the checker as breaking its own standard.
        """
        ok = CLEAN.replace("def add(", 'SHEBANG = "#!/usr/bin/env python3"\n\n\ndef add(')
        path = write(tmp_path, ok)
        assert "shebang" not in rules_for(path)

    def test_a_missing_final_newline_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that a file not ending in a newline is caught.

        Parameters:
            tmp_path: Directory the file is written into.

        Implementation notes:
            The trailing newline is the line terminator every text tool expects, and its absence shows up in a diff as a note on the last line of an otherwise unrelated change.
        """
        path = write(tmp_path, CLEAN.rstrip("\n"))
        assert "newline" in rules_for(path)

    def test_an_unparseable_file_is_reported_not_raised(self, tmp_path):
        """
        Purpose:
            Pin that a file the parser cannot read is reported as one violation rather than ending the run.

        Parameters:
            tmp_path: Directory the file is written into.

        Implementation notes:
            The checker runs over every file before a push, so raising on the first unparseable one would hide every other problem behind it.
        """
        path = write(tmp_path, CLEAN + "\ndef broken(:\n")
        checked, violations = checker.run([str(path)])
        assert checked == 1
        assert {v.rule for v in violations} == {"syntax"}


class TestDocstringPresence:
    """
    Purpose:
        That every module, class and function carries a docstring, in the required form.
    """
    def test_a_module_without_a_docstring_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that a module with no docstring is caught.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        bad = "#!/usr/bin/env python3\nVALUE = 1\n"
        path = write(tmp_path, bad)
        assert "docstring" in rules_for(path)

    def test_a_module_docstring_below_other_code_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that a string placed after other statements does not count as the module's docstring.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        bad = '#!/usr/bin/env python3\nVALUE = 1\n"""\nPurpose:\n    Late.\n"""\n'
        path = write(tmp_path, bad)
        assert "docstring" in rules_for(path)

    def test_a_function_without_a_docstring_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that a function with no docstring is caught.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        bad = CLEAN + "\n\ndef bare():\n    return 1\n"
        path = write(tmp_path, bad)
        assert "docstring" in rules_for(path)

    def test_a_class_without_a_docstring_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that a class with no docstring is caught.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        bad = CLEAN + "\n\nclass Bare:\n    value = 1\n"
        path = write(tmp_path, bad)
        assert "docstring" in rules_for(path)

    def test_a_nested_function_without_a_docstring_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that a function defined inside another function is checked too.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        bad = CLEAN.replace(
            "    return left + right",
            "    def helper():\n        return 1\n    return helper() + left + right")
        path = write(tmp_path, bad)
        assert "docstring" in rules_for(path)

    def test_a_function_defined_under_a_conditional_is_still_checked(self, tmp_path):
        """
        Purpose:
            Pin that a function defined inside a conditional is checked too.

        Parameters:
            tmp_path: Directory the file is written into.

        Implementation notes:
            Walking only the direct children of a module or class misses these entirely, which is a gap that stayed invisible until it was pinned, because the files that have such definitions are few.
        """
        bad = CLEAN + "\n\nif True:\n    def guarded():\n        return 1\n"
        path = write(tmp_path, bad)
        assert "docstring" in rules_for(path)

    def test_a_second_string_under_the_docstring_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that a bare string sitting directly under a docstring is caught.

        Parameters:
            tmp_path: Directory the file is written into.

        Implementation notes:
            Only the first string counts as the docstring, so a second one renders as a duplicated block and is otherwise invisible: every other rule here reads the first statement and stops.
        """
        head, rest = CLEAN.split('"""\n', 2)[:2], CLEAN.split('"""\n', 2)[2]
        bad = '"""\n'.join(head) + '"""\n\n"""\nPurpose:\n    A stray copy.\n"""\n' + rest
        path = write(tmp_path, bad)
        assert "docstring" in rules_for(path)

    def test_single_quote_triples_are_caught(self, tmp_path):
        """
        Purpose:
            Pin that a docstring written with the other triple quote is caught.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        bad = CLEAN.replace('"""\nModule: sample', "'''\nModule: sample", 1)
        bad = bad.replace(
            "    A module that satisfies every rule, used as the baseline the rule tests mutate.\n\"\"\"",
            "    A module that satisfies every rule, used as the baseline the rule tests mutate.\n'''")
        path = write(tmp_path, bad)
        assert "quotes" in rules_for(path)


class TestSectionRules:
    """
    Purpose:
        The grammar of a docstring: which headings are allowed, which are required, and what they may contain.
    """
    def test_a_missing_purpose_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that a docstring with no statement of purpose is caught.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        bad = CLEAN.replace("Purpose:\n        Add two numbers.",
                            "Returns:\n        Their sum, described without a purpose.")
        path = write(tmp_path, bad)
        assert "section" in rules_for(path)

    def test_an_unknown_heading_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that a heading outside the permitted set is caught.

        Parameters:
            tmp_path: Directory the file is written into.

        Implementation notes:
            A fixed set of headings is what makes the docstrings uniform enough to read quickly, and an invented one is usually prose that belongs under an existing heading.
        """
        bad = CLEAN.replace("    Returns:\n        Their sum.",
                            "    Notes:\n        Something.\n\n    Returns:\n        Their sum.")
        path = write(tmp_path, bad)
        assert "section" in rules_for(path)

    def test_a_repeated_heading_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that the same heading appearing twice is caught.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        bad = CLEAN.replace("    Returns:\n        Their sum.",
                            "    Returns:\n        Their sum.\n\n    Returns:\n        Again.")
        path = write(tmp_path, bad)
        assert "section" in rules_for(path)

    def test_an_empty_section_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that a heading with nothing under it is caught.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        bad = CLEAN.replace("    Returns:\n        Their sum.",
                            "    Complexity:\n\n    Returns:\n        Their sum.")
        path = write(tmp_path, bad)
        assert "section" in rules_for(path)

    def test_a_module_line_on_a_function_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that the module heading is rejected anywhere but on a module docstring.

        Parameters:
            tmp_path: Directory the file is written into.

        Implementation notes:
            This rule silently never fired until the checker dedented a docstring before reading its headings, because the pattern required no indentation, which is only ever true of a module's own docstring.
        """
        bad = CLEAN.replace("    Purpose:\n        Add two numbers.",
                            "    Module: nope\n\n    Purpose:\n        Add two numbers.")
        path = write(tmp_path, bad)
        assert "section" in rules_for(path)

    def test_a_missing_module_line_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that a module docstring not naming its module is caught.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        bad = CLEAN.replace("Module: sample\n\n", "")
        path = write(tmp_path, bad)
        assert "section" in rules_for(path)

    def test_a_wrong_module_name_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that a module docstring naming the wrong module is caught.

        Parameters:
            tmp_path: Directory the file is written into.

        Implementation notes:
            A wrong name is what a copied file leaves behind, and it is worse than no name because it reads as correct.
        """
        bad = CLEAN.replace("Module: sample", "Module: something.else")
        path = write(tmp_path, bad)
        assert "module-name" in rules_for(path)


class TestParameterRules:
    """
    Purpose:
        That a docstring documents exactly the parameters its function takes.
    """
    def test_an_undocumented_parameter_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that a parameter with no entry is caught.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        bad = CLEAN.replace("        right: The second number.\n", "")
        path = write(tmp_path, bad)
        assert "parameters" in rules_for(path)

    def test_a_documented_parameter_that_does_not_exist_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that an entry naming something the function does not take is caught.

        Parameters:
            tmp_path: Directory the file is written into.

        Implementation notes:
            This is the rule that catches a docstring written from a remembered signature rather than the real one, which is how a docstring ends up confidently describing arguments that were never there.
        """
        bad = CLEAN.replace("        right: The second number.",
                            "        right: The second number.\n        nonexistent: Not real.")
        path = write(tmp_path, bad)
        assert "parameters" in rules_for(path)

    def test_a_missing_parameters_section_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that a function taking arguments with no parameters section at all is caught.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        bad = CLEAN.replace(
            "    Parameters:\n        left: The first number.\n        right: The second number.\n\n",
            "")
        path = write(tmp_path, bad)
        assert "parameters" in rules_for(path)

    def test_self_and_cls_need_no_documenting(self, tmp_path):
        """
        Purpose:
            Pin that a method's implicit receiver needs no entry.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        source = CLEAN + '''

class Holder:
    """
    Purpose:
        Hold a value.
    """

    def get(self):
        """
        Purpose:
            Return the value.

        Returns:
            The value.
        """
        return 1
'''
        path = write(tmp_path, source)
        assert "parameters" not in rules_for(path)

    def test_a_real_parameter_named_cls_is_accepted_when_documented(self, tmp_path):
        """
        Purpose:
            Pin that an ordinary parameter which happens to be named like a receiver is accepted once documented.

        Parameters:
            tmp_path: Directory the file is written into.

        Implementation notes:
            Parametrized tests over classes really do take such a parameter, and exempting the name everywhere rather than only in the leading position reported their docstrings as documenting something that is not a parameter.
        """
        source = CLEAN + '''

class Cases:
    """
    Purpose:
        Hold parametrized cases.
    """

    def check(self, cls):
        """
        Purpose:
            Check one class.

        Parameters:
            cls: The class under test.
        """
        assert cls
'''
        path = write(tmp_path, source)
        assert rules_for(path) == set()

    def test_a_real_parameter_named_cls_is_caught_when_undocumented(self, tmp_path):
        """
        Purpose:
            Pin that the same parameter is still required to be documented.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        source = CLEAN + '''

class Cases:
    """
    Purpose:
        Hold parametrized cases.
    """

    def check(self, cls):
        """
        Purpose:
            Check one class.
        """
        assert cls
'''
        path = write(tmp_path, source)
        assert "parameters" in rules_for(path)

    def test_a_plain_functions_first_parameter_named_cls_must_be_documented(self, tmp_path):
        """
        Purpose:
            Pin that a module-level function whose first parameter is named like a receiver is still required to document it.

        Parameters:
            tmp_path: Directory the file is written into.

        Implementation notes:
            A plain function has no receiver at all, so dropping its leading argument on the strength of the name alone exempted a real parameter, which helpers that build a class descriptor do have.
        """
        source = CLEAN + '''

def describe(cls):
    """
    Purpose:
        Describe a class.

    Returns:
        Its name.
    """
    return cls
'''
        path = write(tmp_path, source)
        assert "parameters" in rules_for(path)

    def test_a_static_methods_first_parameter_is_a_real_parameter(self, tmp_path):
        """
        Purpose:
            Pin that a static method's leading argument must be documented whatever it is named.

        Parameters:
            tmp_path: Directory the file is written into.

        Implementation notes:
            A static method takes no receiver, so exempting its first argument would silently excuse an undocumented parameter.
        """
        source = CLEAN + '''

class Holder:
    """
    Purpose:
        Hold a helper.
    """

    @staticmethod
    def describe(cls):
        """
        Purpose:
            Describe a class.

        Returns:
            Its name.
        """
        return cls
'''
        path = write(tmp_path, source)
        assert "parameters" in rules_for(path)

    def test_comma_separated_attribute_entries_are_accepted(self, tmp_path):
        """
        Purpose:
            Pin that one entry covering several names at once is accepted.

        Parameters:
            tmp_path: Directory the file is written into.

        Implementation notes:
            A group of attributes that differ only in value is clearer described once than repeated, and the entry pattern was originally too narrow to allow it.
        """
        source = CLEAN + '''

class Palette:
    """
    Purpose:
        Hold colour codes.

    Attributes:
        RED, GREEN, BLUE: Foreground colours.
        RESET: Restores the default.
    """

    RED = "r"
'''
        path = write(tmp_path, source)
        assert rules_for(path) == set()


class TestReturnRules:
    """
    Purpose:
        That a function producing a value says what it produces.
    """
    def test_a_missing_returns_section_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that a function returning a value with no returns section is caught.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        bad = CLEAN.replace("\n    Returns:\n        Their sum.\n", "\n")
        path = write(tmp_path, bad)
        assert "returns" in rules_for(path)

    def test_a_generator_needs_a_returns_section(self, tmp_path):
        """
        Purpose:
            Pin that a function yielding values also needs one.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        bad = CLEAN + '''

def counter():
    """
    Purpose:
        Yield one value.
    """
    yield 1
'''
        path = write(tmp_path, bad)
        assert "returns" in rules_for(path)

    def test_a_bare_return_needs_no_returns_section(self, tmp_path):
        """
        Purpose:
            Pin that a return with no value needs no section.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        ok = CLEAN + '''

def nothing():
    """
    Purpose:
        Do nothing and say nothing.
    """
    return
'''
        path = write(tmp_path, ok)
        assert "returns" not in rules_for(path)

    def test_a_nested_return_is_not_attributed_to_the_parent(self, tmp_path):
        """
        Purpose:
            Pin that a helper's return does not force a returns section onto the function enclosing it.

        Parameters:
            tmp_path: Directory the file is written into.

        Implementation notes:
            Walking every descendant rather than only the function's own statements attributes a nested function's returns to its parent, which reports a function that returns nothing as undocumented.
        """
        ok = CLEAN + '''

def outer():
    """
    Purpose:
        Define a helper and discard it.
    """

    def helper():
        """
        Purpose:
            Produce a number.

        Returns:
            The number.
        """
        return 1

    helper()
'''
        path = write(tmp_path, ok)
        assert "returns" not in rules_for(path)


class TestFormatRules:
    """
    Purpose:
        The formatting rules: one line per paragraph, no trailing space, and nothing credential-shaped.
    """
    def test_hard_wrapped_prose_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that a paragraph broken across lines is caught.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        bad = CLEAN.replace(
            "    A module that satisfies every rule, used as the baseline the rule tests mutate.",
            "    A module that satisfies every rule, used as the\n    baseline the rule tests mutate.")
        path = write(tmp_path, bad)
        assert "wrapping" in rules_for(path)

    def test_trailing_whitespace_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that space left at the end of a docstring line is caught.

        Parameters:
            tmp_path: Directory the file is written into.
        """
        bad = CLEAN.replace("        Their sum.", "        Their sum.   ")
        path = write(tmp_path, bad)
        assert "whitespace" in rules_for(path)

    def test_usage_and_examples_keep_their_line_breaks(self, tmp_path):
        """
        Purpose:
            Pin that the sections holding literal commands are exempt from the one-line rule.

        Parameters:
            tmp_path: Directory the file is written into.

        Implementation notes:
            Those sections hold commands meant to be copied, so joining their lines would produce something that does not run.
        """
        ok = CLEAN.replace(
            "Purpose:\n    A module that satisfies every rule, used as the baseline the rule tests mutate.",
            "Purpose:\n    A module with a usage block.\n\n"
            "Usage:\n    python -m thing --first\n    python -m thing --second\n\n"
            "Examples:\n    thing one\n    thing two")
        path = write(tmp_path, ok)
        assert "wrapping" not in rules_for(path)

    def test_credential_shaped_text_is_caught(self, tmp_path):
        """
        Purpose:
            Pin that text shaped like a credential in a docstring is caught.

        Parameters:
            tmp_path: Directory the file is written into.

        Security considerations:
            The value used here is a published placeholder, not a real credential. The rule exists because a key pasted into a comment while debugging is committed as readily as one pasted into code, and is far less likely to be noticed in review.
        """
        bad = CLEAN.replace("        Their sum.",
                            "        Their sum, keyed by api_key=AKIAIOSFODNN7EXAMPLE.")
        path = write(tmp_path, bad)
        assert "secret" in rules_for(path)


class TestTheShippedCodeComplies:
    """
    Purpose:
        That the real code satisfies the standard, which is what the push gate actually enforces.
    """
    def test_the_package_is_clean(self):
        """
        Purpose:
            Pin that every file in the package passes, and that files were actually checked.

        Implementation notes:
            The count is asserted as well as the result, so a run that found nothing to check cannot pass as a clean one.
        """
        checked, violations = checker.run([str(PACKAGE_ROOT)])
        assert checked > 0
        assert violations == [], "\n".join(str(v) for v in violations[:25])

    def test_the_checker_satisfies_its_own_standard(self):
        """
        Purpose:
            Pin that the checker itself passes the standard it enforces.

        Implementation notes:
            A standard its own checker cannot meet is not one to ask anyone else to follow.
        """
        assert checker.check_path(CHECKER_PATH) == []

    def test_vendored_trees_are_skipped(self, tmp_path):
        """
        Purpose:
            Pin that third-party directories are not collected for checking.

        Parameters:
            tmp_path: Directory the vendored tree is created in.

        Implementation notes:
            That code was written elsewhere and cannot be changed here, so reporting it would drown the real violations and make the gate impossible to pass.
        """
        vendored = tmp_path / "node_modules" / "pkg"
        vendored.mkdir(parents=True)
        (vendored / "thing.py").write_text("x = 1\n", encoding="utf-8")
        assert checker.iter_python_files([str(tmp_path)]) == []


class TestCommandLine:
    """
    Purpose:
        The checker as a command, which is how the hook and the continuous integration run it.
    """
    def test_a_clean_run_exits_zero(self):
        """
        Purpose:
            Pin that a clean run exits successfully.
        """
        result = subprocess.run(
            [sys.executable, str(CHECKER_PATH), str(PACKAGE_ROOT)],
            capture_output=True, text=True, cwd=REPO_ROOT)
        assert result.returncode == 0, result.stdout + result.stderr

    def test_a_dirty_run_exits_one_and_names_the_file(self, tmp_path):
        """
        Purpose:
            Pin that a run with violations exits unsuccessfully and names the offending file.

        Parameters:
            tmp_path: Directory the offending file is written into.

        Implementation notes:
            The exit status is what the hook reads, and the named file is what the developer reads, so both are asserted.
        """
        bad = write(tmp_path, "x = 1\n", name="offender.py")
        result = subprocess.run(
            [sys.executable, str(CHECKER_PATH), str(bad)],
            capture_output=True, text=True, cwd=REPO_ROOT)
        assert result.returncode == 1
        assert "offender.py" in result.stdout

    def test_json_output_is_machine_readable(self, tmp_path):
        """
        Purpose:
            Pin the shape of the machine-readable output, including the fields on each violation.

        Parameters:
            tmp_path: Directory the offending file is written into.
        """
        import json
        bad = write(tmp_path, "x = 1\n", name="offender.py")
        result = subprocess.run(
            [sys.executable, str(CHECKER_PATH), "--json", str(bad)],
            capture_output=True, text=True, cwd=REPO_ROOT)
        payload = json.loads(result.stdout)
        assert payload["files_checked"] == 1
        assert payload["violations"]
        assert {"path", "symbol", "rule", "detail"} == set(payload["violations"][0])


@pytest.mark.parametrize("name", ["pre-push"])
def test_the_hook_is_present_and_executable(name):
    """
    Purpose:
        Pin that the push hook exists in the repository and is executable.

    Parameters:
        name: The hook's filename.

    Implementation notes:
        The hook is kept in the repository rather than in the local hooks directory so that one configuration setting points every clone at it, but a file that is not executable is silently ignored, which would leave the gate off with nothing saying so.
    """
    hook = REPO_ROOT / ".githooks" / name
    assert hook.is_file(), "missing .githooks/%s" % name
    assert hook.stat().st_mode & 0o111, "hook is not executable"
