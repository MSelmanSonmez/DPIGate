#!/usr/bin/env python3
"""
installer-gui.py — graphical setup wizard for DPIGate (Linux).

Windows-style Next → Next → Finish flow built on Gtk.Assistant (the same
GTK3/PyGObject stack tray.py already requires — no new dependency):

  1 Welcome      2 License      3 Components      4 Administrator password
  5 Ready        6 Installing   7 Finished

The wizard NEVER reimplements installation. It collects options, then runs
`install.sh --cli <flags>` as a child process and streams its output into the
progress page, so the graphical and the text install are the same code path.
install.sh hands over to this file automatically when it is started without a
controlling terminal (double-clicked in a file manager) — see _gui_wanted()
there.

Usage:
  installer-gui.py --installer /path/to/install.sh [preset flags ...]

Preset flags (all optional) pre-tick the matching component checkbox:
  --system --start --no-build --assume-deps --autostart --no-shortcut

Test entry points (used by the project's verification runs, not by users):
  --self-test          build every page, walk the whole flow unattended and
                       run the child as `--cli --check-only`; exit 0 on success
  --auto-install       same unattended walk, but performs the REAL install with
                       the preset flags
  --shot-dir DIR       save a PNG of every page during a test walk
"""
import os
import sys
import shutil
import subprocess
import threading

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib, GdkPixbuf, Gdk, Pango  # noqa: E402

APP_TITLE = "DPIGate"


# ── Helpers ──────────────────────────────────────────────────────────────────
def _plat(script_dir: str, verb: str) -> str:
    """One-shot lib/platform.sh probe. Never raises: the welcome page must
    render even on a host where the probe fails."""
    plat = os.path.join(script_dir, "lib", "platform.sh")
    if not os.path.exists(plat):
        return "?"
    try:
        out = subprocess.run(["bash", plat, verb], capture_output=True, text=True,
                             timeout=15)
        return (out.stdout or "").strip() or "?"
    except (OSError, subprocess.SubprocessError):
        return "?"


def _sudo_password_needed() -> bool:
    """True when a password page is worth showing.

    root, NOPASSWD sudo and sudo-less hosts all skip it — on the last one
    install.sh escalates through pkexec/run0, which prompt on their own.
    """
    if os.geteuid() == 0:
        return False
    if not shutil.which("sudo"):
        return False
    try:
        return subprocess.run(["sudo", "-n", "true"], capture_output=True,
                              timeout=10).returncode != 0
    except (OSError, subprocess.SubprocessError):
        return False


def _read_license(script_dir: str) -> str:
    """LICENSE sits in the repo root during development and next to install.sh
    in the dist tarball (scripts/make-dist.sh copies it there)."""
    for cand in (os.path.join(script_dir, "LICENSE"),
                 os.path.join(os.path.dirname(script_dir), "LICENSE")):
        try:
            with open(cand, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            continue
    return ("LICENSE file not found next to the installer.\n"
            "DPIGate is distributed under the Apache License 2.0.")


# install.sh milestones → progress bar fraction. Anything unmatched just
# scrolls in the log; the bar only ever moves forward.
_PROGRESS_MARKS = (
    ("[install] distro:", 0.05),
    ("[install] building", 0.20),
    ("[install] copying files", 0.50),
    ("[install] setting capabilities", 0.62),
    ("[install] loading firewall rules", 0.72),
    ("[install] installing as a system service", 0.80),
    ("[install] user-mode install", 0.80),
    ("OK: start menu shortcut", 0.90),
    ("skip: --no-shortcut", 0.90),
    ("[install] RESULT:", 1.0),
    ("[install] complete", 1.0),
)


class Wizard:
    def __init__(self, installer: str, presets, shot_dir=None):
        self.installer = os.path.abspath(installer)
        self.script_dir = os.path.dirname(self.installer)
        self.presets = set(presets)
        self.shot_dir = shot_dir
        self.shot_seq = 0

        self.proc = None
        self.install_rc = None
        self.saw_result_ok = False
        self.sudo_password = None
        self.child_extra_args = []      # test hook: e.g. ["--check-only"]
        self.exit_code = 1

        self.asst = Gtk.Assistant()
        self.asst.set_title("%s Setup" % APP_TITLE)
        self.asst.set_default_size(660, 520)
        self.asst.set_position(Gtk.WindowPosition.CENTER)
        icon = os.path.join(self.script_dir, "icon.png")
        if os.path.exists(icon):
            try:
                self.asst.set_icon(GdkPixbuf.Pixbuf.new_from_file(icon))
            except GLib.Error:
                pass

        self.asst.connect("cancel", self.on_cancel)
        self.asst.connect("close", self.on_close)
        self.asst.connect("prepare", self.on_prepare)

        self._build_pages()
        self._relabel_buttons()

    # ── Pages ───────────────────────────────────────────────────────────────
    def _add(self, widget, ptype, title, complete=True):
        widget.set_border_width(18)
        self.asst.append_page(widget)
        self.asst.set_page_type(widget, ptype)
        self.asst.set_page_title(widget, title)
        self.asst.set_page_complete(widget, complete)
        return widget

    def _build_pages(self):
        self.page_welcome = self._add(self._welcome_page(),
                                      Gtk.AssistantPageType.INTRO,
                                      "Welcome")
        self.page_license = self._add(self._license_page(),
                                      Gtk.AssistantPageType.CONTENT,
                                      "License Agreement",
                                      complete=False)
        self.page_components = self._add(self._components_page(),
                                         Gtk.AssistantPageType.CONTENT,
                                         "Components")
        self.page_password = None
        if _sudo_password_needed():
            self.page_password = self._add(self._password_page(),
                                           Gtk.AssistantPageType.CONTENT,
                                           "Administrator Password",
                                           complete=False)
        self.page_ready = self._add(self._ready_page(),
                                    Gtk.AssistantPageType.CONFIRM,
                                    "Ready to Install")
        self.page_progress = self._add(self._progress_page(),
                                       Gtk.AssistantPageType.PROGRESS,
                                       "Installing",
                                       complete=False)
        self.page_done = self._add(self._done_page(),
                                   Gtk.AssistantPageType.SUMMARY,
                                   "Finished")

    def _welcome_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        head = Gtk.Label()
        head.set_markup("<span size='xx-large' weight='bold'>%s</span>" % APP_TITLE)
        head.set_xalign(0)
        box.pack_start(head, False, False, 0)

        intro = Gtk.Label(label="This wizard installs DPIGate, a DPI bypass with\n"
            "per-program filtering, on this computer.\n\n"
            "Click Next to continue.")
        intro.set_xalign(0)
        box.pack_start(intro, False, False, 0)

        grid = Gtk.Grid(column_spacing=18, row_spacing=6)
        grid.set_halign(Gtk.Align.START)
        rows = (
            ("Distribution", _plat(self.script_dir, "distro")),
            ("Package manager", _plat(self.script_dir, "pkgmgr")),
            ("Init system", _plat(self.script_dir, "init-system")),
            ("Firewall backend", _plat(self.script_dir, "fw-backend")),
        )
        for i, (k, v) in enumerate(rows):
            lk = Gtk.Label(label="%s:" % k, xalign=1)
            lk.get_style_context().add_class("dim-label")
            lv = Gtk.Label(xalign=0)
            lv.set_markup("<tt>%s</tt>" % GLib.markup_escape_text(v))
            grid.attach(lk, 0, i, 1, 1)
            grid.attach(lv, 1, i, 1, 1)
        box.pack_start(grid, False, False, 8)
        return box

    def _license_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        lbl = Gtk.Label(label="Please review the license terms before installing.")
        lbl.set_xalign(0)
        box.pack_start(lbl, False, False, 0)

        view = Gtk.TextView()
        view.set_editable(False)
        view.set_cursor_visible(False)
        view.set_wrap_mode(Gtk.WrapMode.WORD)
        view.get_buffer().set_text(_read_license(self.script_dir))
        sw = Gtk.ScrolledWindow()
        sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sw.set_shadow_type(Gtk.ShadowType.IN)
        sw.add(view)
        box.pack_start(sw, True, True, 0)

        self.chk_license = Gtk.CheckButton(
            label="I accept the terms of the license agreement")
        self.chk_license.connect(
            "toggled",
            lambda b: self.asst.set_page_complete(self.page_license, b.get_active()))
        box.pack_start(self.chk_license, False, False, 0)
        return box

    def _components_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        lbl = Gtk.Label(label="Choose what the installer should do.")
        lbl.set_xalign(0)
        box.pack_start(lbl, False, False, 4)

        prebuilt = os.access(os.path.join(self.script_dir, "goodbyedpi"), os.X_OK)
        self.chk_build = Gtk.CheckButton(
            label="Build from source (recommended)")
        self.chk_build.set_active("--no-build" not in self.presets)
        self.chk_shortcut = Gtk.CheckButton(
            label="Create an application-menu shortcut (Internet)")
        self.chk_shortcut.set_active("--no-shortcut" not in self.presets)
        self.chk_autostart = Gtk.CheckButton(
            label="Start automatically at login")
        self.chk_autostart.set_active("--autostart" in self.presets)
        self.chk_service = Gtk.CheckButton(
            label="Install a system-wide service (advanced)")
        self.chk_service.set_active("--system" in self.presets)
        self.chk_launch = Gtk.CheckButton(
            label="Launch DPIGate when setup finishes")
        self.chk_launch.set_active(True)

        for w in (self.chk_build, self.chk_shortcut, self.chk_autostart,
                  self.chk_service, self.chk_launch):
            box.pack_start(w, False, False, 0)

        if prebuilt:
            hint = Gtk.Label()
            hint.set_markup("<i>%s</i>" % GLib.markup_escape_text(
                "A compiled binary already exists; unticking the build box "
                "reuses it."))
            hint.set_xalign(0)
            hint.set_line_wrap(True)
            box.pack_start(hint, False, False, 8)
        return box

    def _password_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        lbl = Gtk.Label(label="Setup needs administrator rights to set capabilities on the\n"
            "goodbyedpi binary and to load the firewall rules.")
        lbl.set_xalign(0)
        box.pack_start(lbl, False, False, 0)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.ent_password = Gtk.Entry()
        self.ent_password.set_visibility(False)
        self.ent_password.set_input_purpose(Gtk.InputPurpose.PASSWORD)
        self.ent_password.set_placeholder_text("Password")
        self.ent_password.set_activates_default(False)
        self.ent_password.connect("activate", lambda *_a: self._check_password())
        btn = Gtk.Button(label="Verify")
        btn.connect("clicked", lambda *_a: self._check_password())
        row.pack_start(self.ent_password, True, True, 0)
        row.pack_start(btn, False, False, 0)
        box.pack_start(row, False, False, 0)

        self.lbl_password = Gtk.Label(label="")
        self.lbl_password.set_xalign(0)
        box.pack_start(self.lbl_password, False, False, 0)
        return box

    # ── Ready page ──────────────────────────────────────────────────────────
    # A two-column grid instead of a pre-padded text block: proportional-font
    # labels never aligned with %-padding, and long paths are ellipsized in
    # the middle instead of wrapping into the next row.
    def _ready_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)

        head = Gtk.Label()
        head.set_markup("<span size='large' weight='bold'>Ready to Install</span>")
        head.set_xalign(0)
        box.pack_start(head, False, False, 0)

        sub = Gtk.Label(label="Setup is ready to install with these settings:")
        sub.set_xalign(0)
        box.pack_start(sub, False, False, 0)

        sep = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        box.pack_start(sep, False, False, 0)

        self.grid_summary = Gtk.Grid(column_spacing=18, row_spacing=10)
        self.grid_summary.set_halign(Gtk.Align.START)
        self._refresh_summary()
        box.pack_start(self.grid_summary, False, False, 0)

        hint = Gtk.Label(label="Click Install to continue.")
        hint.get_style_context().add_class("dim-label")
        hint.set_xalign(0)
        box.pack_start(hint, False, False, 0)
        return box

    def _bool_cell(self, on: bool) -> Gtk.Box:
        cell = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        img = Gtk.Image.new_from_icon_name(
            "object-select-symbolic" if on else "window-close-symbolic",
            Gtk.IconSize.MENU)
        cell.pack_start(img, False, False, 0)
        lbl = Gtk.Label(label="yes" if on else "no", xalign=0)
        cell.pack_start(lbl, False, False, 0)
        return cell

    def _refresh_summary(self):
        """Rebuild the summary grid from the current checkbox state. Called on
        every "prepare" of the page so backing up and re-checking a component
        is reflected when the page is shown again."""
        if not hasattr(self, "grid_summary"):
            return
        for child in self.grid_summary.get_children():
            self.grid_summary.remove(child)

        data = os.path.join(os.environ.get(
            "XDG_DATA_HOME", os.path.expanduser("~/.local/share")), "DPIGate")
        conf = os.path.join(os.environ.get(
            "XDG_CONFIG_HOME", os.path.expanduser("~/.config")), "DPIGate")
        rows = (
            ("Program files", "path", data),
            ("Configuration", "path", conf),
            ("Build from source", "bool", self.chk_build.get_active()),
            ("Menu shortcut", "bool", self.chk_shortcut.get_active()),
            ("Start at login", "bool", self.chk_autostart.get_active()),
            ("System service", "bool", self.chk_service.get_active()),
        )
        for i, (key, kind, val) in enumerate(rows):
            lk = Gtk.Label(label="%s:" % key, xalign=1)
            lk.get_style_context().add_class("dim-label")
            if kind == "path":
                lv = Gtk.Label(xalign=0, selectable=True)
                lv.set_markup("<tt>%s</tt>" % GLib.markup_escape_text(val))
                lv.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
                lv.set_max_width_chars(44)
                lv.set_tooltip_text(val)
            else:
                lv = self._bool_cell(val)
            self.grid_summary.attach(lk, 0, i, 1, 1)
            self.grid_summary.attach(lv, 1, i, 1, 1)
        self.grid_summary.show_all()

    def _progress_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.bar = Gtk.ProgressBar()
        self.bar.set_show_text(True)
        self.bar.set_text("Preparing…")
        box.pack_start(self.bar, False, False, 0)

        self.log_view = Gtk.TextView()
        self.log_view.set_editable(False)
        self.log_view.set_cursor_visible(False)
        self.log_view.set_monospace(True)
        self.log_view.set_wrap_mode(Gtk.WrapMode.CHAR)
        sw = Gtk.ScrolledWindow()
        sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sw.set_shadow_type(Gtk.ShadowType.IN)
        sw.add(self.log_view)
        box.pack_start(sw, True, True, 0)
        return box

    def _done_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.lbl_done = Gtk.Label(label="")
        self.lbl_done.set_xalign(0)
        self.lbl_done.set_line_wrap(True)
        box.pack_start(self.lbl_done, False, False, 0)
        return box

    # ── Button labels ───────────────────────────────────────────────────────
    def _relabel_buttons(self):
        """Force English labels on Gtk.Assistant's stock navigation buttons.

        GTK translates Cancel/Back/Next/Apply/Finish for the host locale and
        renders its own words for them on a non-English desktop; the wizard
        is English-only. The match set is built from GTK's own lookups — the
        plain message id, dgettext, and the stock-item label — so every
        locale's rendering is covered without hardcoding a single foreign
        word. Any label GTK renames is left alone."""
        def key(text):
            return text.replace("_", "").strip().lower()

        # Message ids GtkAssistant (GTK 3) renders its action buttons from,
        # mapped to the labels a setup wizard shows. Assistant versions differ:
        # GTK 3.24 uses "_Next"/"_Finish", older ones "_Forward"/"_Close";
        # the gtk-* stock ids are covered for completeness.
        want = {}
        ids = {
            "_Cancel": "Cancel",
            "_Back": "Back",
            "_Next": "Next",
            "_Forward": "Next",
            "_Apply": "Install",
            "_Finish": "Finish",
            "_Close": "Finish",
            "gtk-cancel": "Cancel",
            "gtk-go-back": "Back",
            "gtk-go-forward": "Next",
            "gtk-apply": "Install",
            "gtk-close": "Finish",
        }
        for msgid, label in ids.items():
            want[key(msgid)] = label
            try:
                want[key(GLib.dgettext("gtk30", msgid))] = label
            except Exception:
                pass
            try:
                item = Gtk.stock_lookup(msgid)
                if item:
                    want[key(item.label)] = label
            except Exception:
                pass

        def walk(widget):
            if isinstance(widget, Gtk.Button):
                lbl = widget.get_label() or ""
                new = want.get(key(lbl))
                if new:
                    widget.set_label(new)
            if isinstance(widget, Gtk.Container):
                for child in widget.get_children():
                    walk(child)

        walk(self.asst)

    # ── Options → install.sh flags ──────────────────────────────────────────
    def flags(self):
        args = ["--cli"]
        if not self.chk_build.get_active():
            args.append("--no-build")
        if not self.chk_shortcut.get_active():
            args.append("--no-shortcut")
        args.append("--autostart" if self.chk_autostart.get_active()
                    else "--no-autostart")
        if self.chk_service.get_active():
            args.append("--system")
        if "--assume-deps" in self.presets:
            args.append("--assume-deps")
        args.extend(self.child_extra_args)
        return args

    # ── Password ────────────────────────────────────────────────────────────
    def _check_password(self):
        pw = self.ent_password.get_text()
        if not pw:
            self.lbl_password.set_markup(
                "<span foreground='#b00'>%s</span>"
                % GLib.markup_escape_text("Enter a password."))
            return False
        try:
            rc = subprocess.run(["sudo", "-S", "-v"], input=pw + "\n", text=True,
                                capture_output=True, timeout=25).returncode
        except (OSError, subprocess.SubprocessError):
            rc = 1
        if rc == 0:
            self.sudo_password = pw
            self.lbl_password.set_markup(
                "<span foreground='#0a0'>%s</span>"
                % GLib.markup_escape_text("Password accepted."))
            self.asst.set_page_complete(self.page_password, True)
            return True
        self.sudo_password = None
        self.asst.set_page_complete(self.page_password, False)
        self.lbl_password.set_markup(
            "<span foreground='#b00'>%s</span>"
            % GLib.markup_escape_text("Wrong password — try again."))
        return False

    # ── Install run ─────────────────────────────────────────────────────────
    def _append_log(self, text):
        buf = self.log_view.get_buffer()
        buf.insert(buf.get_end_iter(), text)
        mark = buf.create_mark(None, buf.get_end_iter(), False)
        self.log_view.scroll_mark_onscreen(mark)
        buf.delete_mark(mark)

    def _on_line(self, line):
        self._append_log(line)
        stripped = line.strip()
        if stripped.startswith("[install] RESULT: ok"):
            self.saw_result_ok = True
        for mark, frac in _PROGRESS_MARKS:
            if mark in stripped and frac > self.bar.get_fraction():
                self.bar.set_fraction(frac)
                self.bar.set_text("%d%%" % int(frac * 100))
                break
        return False

    def _reader(self, proc):
        for raw in iter(proc.stdout.readline, ""):
            GLib.idle_add(self._on_line, raw)
        proc.stdout.close()
        rc = proc.wait()
        GLib.idle_add(self._install_finished, rc)

    def start_install(self):
        if self.proc is not None:
            return
        env = dict(os.environ)
        env["GDPI_INSTALL_GUI"] = "0"       # child must never re-enter the wizard
        if self.sudo_password:
            env["SUDO_PASSWORD"] = self.sudo_password
        cmd = ["bash", self.installer] + self.flags()
        self._append_log("$ %s\n" % " ".join(cmd[1:]))
        try:
            self.proc = subprocess.Popen(
                cmd, cwd=self.script_dir, env=env, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1,
                start_new_session=True)
        except OSError as exc:
            self._append_log("ERROR: %s\n" % exc)
            self._install_finished(127)
            return
        self.bar.set_fraction(0.02)
        self.bar.set_text("Installing…")
        threading.Thread(target=self._reader, args=(self.proc,), daemon=True).start()

    def _will_launch(self):
        """A --check-only walk installs nothing, so there is nothing to run."""
        return "--check-only" not in self.child_extra_args

    def _install_finished(self, rc):
        self.install_rc = rc
        self.proc = None
        ok = (rc == 0)
        self.bar.set_fraction(1.0 if ok else self.bar.get_fraction())
        self.bar.set_text("Done" if ok else "Failed")
        self.asst.set_page_complete(self.page_progress, True)

        if ok:
            msg = "DPIGate has been installed successfully."
            if not self.saw_result_ok and "--check-only" not in self.child_extra_args:
                msg += "\n" + "Note: the installer did not report a completion marker."
            # Same condition on_close() launches under: a --check-only test
            # walk must not promise a launch that will not happen.
            if self.chk_launch.get_active() and self._will_launch():
                msg += "\n\n" + "DPIGate will start when you click Finish."
            self.lbl_done.set_markup(
                "<span size='large' weight='bold'>%s</span>\n\n%s"
                % (GLib.markup_escape_text("Setup complete"),
                   GLib.markup_escape_text(msg)))
        else:
            self.lbl_done.set_markup(
                "<span size='large' weight='bold' foreground='#b00'>%s</span>\n\n%s"
                % (GLib.markup_escape_text("Setup failed"),
                   GLib.markup_escape_text(
                       "install.sh exited with code %d. The log on the previous "
                       "page has the details. Nothing needs to be undone by hand; "
                       "re-running setup is safe, and ./uninstall.sh removes a "
                       "partial install." % rc)))
        self.exit_code = 0 if ok else 1
        self.asst.next_page()
        return False

    # ── Assistant signals ───────────────────────────────────────────────────
    def on_prepare(self, _asst, page):
        if page is self.page_ready:
            self._refresh_summary()
        elif page is self.page_progress:
            self.start_install()
        self._snapshot()

    def on_cancel(self, _asst):
        if self.proc is not None:
            dlg = Gtk.MessageDialog(
                transient_for=self.asst, modal=True,
                message_type=Gtk.MessageType.QUESTION,
                buttons=Gtk.ButtonsType.NONE,
                text="Abort the installation?")
            # Stock YES_NO buttons would render in the host locale; the wizard
            # is English-only, so add the labels explicitly.
            dlg.add_button("No", Gtk.ResponseType.NO)
            dlg.add_button("Yes", Gtk.ResponseType.YES)
            dlg.format_secondary_text(
                "The install is running. Aborting can leave a partial install; "
                "run ./uninstall.sh afterwards to clean up.")
            answer = dlg.run()
            dlg.destroy()
            if answer != Gtk.ResponseType.YES:
                return
            try:
                os.killpg(os.getpgid(self.proc.pid), 15)
            except OSError:
                pass
        self.exit_code = 1
        Gtk.main_quit()

    def on_close(self, _asst):
        if self.install_rc == 0 and self.chk_launch.get_active() \
                and self._will_launch():
            data_dir = os.path.join(os.environ.get(
                "XDG_DATA_HOME", os.path.expanduser("~/.local/share")),
                "DPIGate")
            start_sh = os.path.join(data_dir, "start.sh")
            if os.access(start_sh, os.X_OK):
                env = dict(os.environ)
                if self.sudo_password:
                    env["SUDO_PASSWORD"] = self.sudo_password
                try:
                    subprocess.Popen([start_sh], cwd=data_dir, env=env,
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL,
                                     start_new_session=True)
                except OSError:
                    pass
        Gtk.main_quit()

    # ── Screenshots (test walks only) ───────────────────────────────────────
    def _snapshot(self):
        if not self.shot_dir:
            return
        win = self.asst.get_window()
        if win is None:
            return
        self.shot_seq += 1
        name = os.path.join(self.shot_dir, "page%02d.png" % self.shot_seq)

        def grab():
            w = self.asst.get_window()
            if w is None:
                return False
            pb = Gdk.pixbuf_get_from_window(w, 0, 0, w.get_width(), w.get_height())
            if pb is not None:
                try:
                    pb.savev(name, "png", [], [])
                except GLib.Error:
                    pass
            return False

        # One main-loop turn later: the page being prepared has not been drawn
        # yet when "prepare" fires.
        GLib.timeout_add(350, grab)

    def run(self):
        self.asst.show_all()
        Gtk.main()
        return self.exit_code


# ── Unattended walk used by the verification runs ────────────────────────────
def _test_walk(wiz: Wizard):
    """Drive the wizard with no user present: accept the licence, keep the
    preset component choices, jump page by page. Exercises the real page
    widgets, the real flag builder and the real child process."""
    seen = []

    def step():
        page_no = wiz.asst.get_current_page()
        page = wiz.asst.get_nth_page(page_no)
        seen.append(page_no)

        if page is wiz.page_license:
            wiz.chk_license.set_active(True)
        if page is wiz.page_password:
            # A test walk has no password to give; the child either needs none
            # or escalates through pkexec/polkit like install.sh always does.
            wiz.asst.set_page_complete(wiz.page_password, True)
        if page is wiz.page_progress:
            if wiz.install_rc is None:
                return True             # keep polling until the child exits
            return True                 # _install_finished advances the page
        if page is wiz.page_done:
            GLib.timeout_add(600, lambda: (wiz.asst.emit("close"), False)[1])
            return False

        wiz.asst.next_page()
        return True

    GLib.timeout_add(500, step)


def main(argv):
    installer = None
    presets = []
    shot_dir = None
    self_test = False
    auto_install = False

    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--installer" and i + 1 < len(argv):
            installer = argv[i + 1]
            i += 2
            continue
        if a == "--shot-dir" and i + 1 < len(argv):
            shot_dir = argv[i + 1]
            i += 2
            continue
        if a == "--self-test":
            self_test = True
        elif a == "--auto-install":
            auto_install = True
        elif a in ("--help", "-h"):
            print(__doc__)
            return 0
        elif a.startswith("--"):
            presets.append(a)
        i += 1

    if installer is None:
        here = os.path.dirname(os.path.abspath(__file__))
        installer = os.path.join(here, "install.sh")
    if not os.path.exists(installer):
        print("FATAL: installer not found: %s" % installer, file=sys.stderr)
        return 2
    if shot_dir:
        os.makedirs(shot_dir, exist_ok=True)

    wiz = Wizard(installer, presets, shot_dir=shot_dir)
    if self_test:
        wiz.child_extra_args = ["--check-only"]
    if self_test or auto_install:
        expected = ["INTRO", "CONTENT", "CONTENT", "CONFIRM", "PROGRESS", "SUMMARY"]
        actual = [wiz.asst.get_page_type(wiz.asst.get_nth_page(n)).value_nick.upper()
                  for n in range(wiz.asst.get_n_pages())]
        if wiz.page_password is not None:
            expected.insert(3, "CONTENT")
        if actual != expected:
            print("FAIL: page types %s != %s" % (actual, expected), file=sys.stderr)
            return 3
        print("OK: %d pages, types %s" % (len(actual), actual))
        _test_walk(wiz)

    rc = wiz.run()
    if self_test or auto_install:
        print("OK: install child exit code %s" % wiz.install_rc)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
