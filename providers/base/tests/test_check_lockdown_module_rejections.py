import unittest
from unittest.mock import Mock, mock_open, patch

from check_lockdown_module_rejections import (
    find_failed_module_inserts,
    find_rejections,
    get_kernel_log,
    get_loaded_modules,
    get_lockdown_state,
    get_module_insert_log,
    get_sig_enforce_state,
    main,
)

REJECTION_LINE = (
    "Lockdown: systemd-udevd: unsigned module loading"
    " is restricted; see man kernel_lockdown.7"
)


class TestGetLockdownState(unittest.TestCase):
    def test_parses_bracketed_mode(self):
        data = "none [integrity] confidentiality"
        with patch("builtins.open", mock_open(read_data=data)):
            result = get_lockdown_state()
        self.assertEqual(result, "integrity")

    def test_returns_unavailable_on_oserror(self):
        with patch("builtins.open", side_effect=OSError):
            result = get_lockdown_state()
        self.assertEqual(result, "unavailable")

    def test_returns_unknown_when_no_brackets(self):
        with patch("builtins.open", mock_open(read_data="none")):
            result = get_lockdown_state()
        self.assertEqual(result, "unknown")


class TestGetSigEnforceState(unittest.TestCase):
    def test_returns_stripped_y(self):
        with patch("builtins.open", mock_open(read_data="Y\n")):
            result = get_sig_enforce_state()
        self.assertEqual(result, "Y")

    def test_returns_unavailable_on_oserror(self):
        with patch("builtins.open", side_effect=OSError):
            result = get_sig_enforce_state()
        self.assertEqual(result, "unavailable")


class TestFindRejections(unittest.TestCase):
    def test_clean_log_returns_empty(self):
        self.assertEqual(find_rejections("normal\nanother"), [])

    def test_matches_lockdown_unsigned_module(self):
        line = (
            "Lockdown: systemd-udevd: unsigned module loading"
            " is restricted; see man kernel_lockdown.7"
        )
        result = find_rejections("prefix\n{}\nsuffix".format(line))
        self.assertEqual(result, [line])

    def test_matches_unavailable_key(self):
        line = "Loading of module with unavailable key is rejected"
        self.assertEqual(find_rejections(line), [line])

    def test_matches_all_four_patterns(self):
        lines = [
            "Lockdown: systemd-udevd: unsigned module loading"
            " is restricted",
            "Loading of unsigned module is rejected",
            "Loading of module with unavailable key is rejected",
            "Loading of module with unsupported crypto is rejected",
        ]
        result = find_rejections("\n".join(lines))
        self.assertEqual(result, lines)


class TestFindFailedModuleInserts(unittest.TestCase):
    def test_extracts_and_deduplicates_both_shapes(self):
        log = (
            "modprobe: ERROR: could not insert 'foo':"
            " Operation not permitted\n"
            "systemd-udevd[123]:"
            " Failed to insert module 'bar':"
            " Operation not permitted\n"
            "modprobe: ERROR: could not insert 'foo':"
            " Operation not permitted\n"
        )
        result = find_failed_module_inserts(log)
        self.assertEqual(result, ["bar", "foo"])


class TestGetKernelLog(unittest.TestCase):
    @patch("check_lockdown_module_rejections.subprocess.run")
    def test_returncode_0_returns_stdout(self, mock_run):
        mock_run.return_value = Mock(
            returncode=0,
            stdout=(
                "Aug 24 kernel: Lockdown: systemd-udevd:"
                " unsigned module loading is restricted\n"
            ),
            stderr="",
        )
        result = get_kernel_log()
        self.assertIn("unsigned module loading is restricted", result)

    @patch("check_lockdown_module_rejections.subprocess.run")
    def test_returncode_1_returns_empty_string(self, mock_run):
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="")
        result = get_kernel_log()
        self.assertEqual(result, "")

    @patch("check_lockdown_module_rejections.subprocess.run")
    def test_other_returncode_raises_systemexit(self, mock_run):
        mock_run.return_value = Mock(
            returncode=2,
            stdout="",
            stderr="Failed to connect to journal",
        )
        with self.assertRaises(SystemExit) as ctx:
            get_kernel_log()
        self.assertIn("Failed to connect to journal", str(ctx.exception))

    @patch("check_lockdown_module_rejections.subprocess.run")
    def test_returncode_1_with_stderr_raises_systemexit(self, mock_run):
        # If journalctl does not recognize -g, it also exits with 1. The
        # test must not show this as a boot without rejections.
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="journalctl: unrecognized option '-g'",
        )
        with self.assertRaises(SystemExit) as ctx:
            get_kernel_log()
        self.assertIn("unrecognized option", str(ctx.exception))

    @patch("check_lockdown_module_rejections.subprocess.run")
    def test_insert_log_degrades_to_empty_on_error(self, mock_run):
        mock_run.return_value = Mock(returncode=2, stdout="", stderr="boom")
        self.assertEqual(get_module_insert_log(), "")


class TestGetLoadedModules(unittest.TestCase):
    def test_parses_and_normalises_names(self):
        data = "snd_hda_intel 57344 3 - Live 0x0\nzfs 1 0 - Live 0x0\n"
        with patch("builtins.open", mock_open(read_data=data)):
            result = get_loaded_modules()
        self.assertEqual(result, {"snd_hda_intel", "zfs"})

    def test_returns_empty_set_on_oserror(self):
        with patch("builtins.open", side_effect=OSError):
            self.assertEqual(get_loaded_modules(), set())


class TestMain(unittest.TestCase):
    @patch("check_lockdown_module_rejections.get_kernel_log")
    @patch("check_lockdown_module_rejections.get_sig_enforce_state")
    @patch("check_lockdown_module_rejections.get_lockdown_state")
    @patch("builtins.print")
    def test_main_exits_zero_on_clean_log(
        self, mock_print, mock_lock, mock_sig, mock_klog
    ):
        mock_lock.return_value = "none"
        mock_sig.return_value = "N"
        mock_klog.return_value = ""
        main()  # This must not raise SystemExit.

    @patch("check_lockdown_module_rejections.get_loaded_modules")
    @patch("check_lockdown_module_rejections.get_module_insert_log")
    @patch("check_lockdown_module_rejections.get_kernel_log")
    @patch("check_lockdown_module_rejections.get_sig_enforce_state")
    @patch("check_lockdown_module_rejections.get_lockdown_state")
    @patch("builtins.print")
    def test_main_flags_module_that_never_loaded(
        self,
        mock_print,
        mock_lock,
        mock_sig,
        mock_klog,
        mock_inserts,
        mock_loaded,
    ):
        mock_lock.return_value = "integrity"
        mock_sig.return_value = "Y"
        mock_klog.return_value = REJECTION_LINE
        mock_inserts.return_value = (
            "modprobe: ERROR: could not insert 'foo':"
            " Operation not permitted"
        )
        mock_loaded.return_value = {"ext4"}
        with self.assertRaises(SystemExit) as ctx:
            main()
        msg = str(ctx.exception)
        self.assertIn("unsigned module loading is restricted", msg)
        self.assertIn("no later load recovered them", msg)
        self.assertIn("foo", msg)

    @patch("check_lockdown_module_rejections.get_loaded_modules")
    @patch("check_lockdown_module_rejections.get_module_insert_log")
    @patch("check_lockdown_module_rejections.get_kernel_log")
    @patch("check_lockdown_module_rejections.get_sig_enforce_state")
    @patch("check_lockdown_module_rejections.get_lockdown_state")
    @patch("builtins.print")
    def test_main_marks_hyphenated_module_loaded_later(
        self,
        mock_print,
        mock_lock,
        mock_sig,
        mock_klog,
        mock_inserts,
        mock_loaded,
    ):
        # The kernel rejects the module from the initramfs, and then loads
        # it from the root filesystem. The test fails, but the report
        # shows that the module loaded later.
        mock_lock.return_value = "integrity"
        mock_sig.return_value = "Y"
        mock_klog.return_value = REJECTION_LINE
        mock_inserts.return_value = (
            "systemd-udevd[241]: Failed to insert module"
            " 'snd-hda-intel': Operation not permitted"
        )
        mock_loaded.return_value = {"snd_hda_intel"}
        with self.assertRaises(SystemExit) as ctx:
            main()
        msg = str(ctx.exception)
        self.assertIn("but in /proc/modules now", msg)
        self.assertIn("snd-hda-intel", msg)
        self.assertNotIn("no later load recovered them", msg)

    @patch("check_lockdown_module_rejections.get_loaded_modules")
    @patch("check_lockdown_module_rejections.get_module_insert_log")
    @patch("check_lockdown_module_rejections.get_kernel_log")
    @patch("check_lockdown_module_rejections.get_sig_enforce_state")
    @patch("check_lockdown_module_rejections.get_lockdown_state")
    @patch("builtins.print")
    def test_main_reports_when_module_cannot_be_named(
        self,
        mock_print,
        mock_lock,
        mock_sig,
        mock_klog,
        mock_inserts,
        mock_loaded,
    ):
        mock_lock.return_value = "integrity"
        mock_sig.return_value = "N"
        mock_klog.return_value = REJECTION_LINE
        mock_inserts.return_value = ""
        mock_loaded.return_value = set()
        with self.assertRaises(SystemExit) as ctx:
            main()
        self.assertIn("cannot be named", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
