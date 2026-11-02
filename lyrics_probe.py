"""Inspect the installed player's class signatures. No player hooks are installed."""

import re
import struct
import zipfile

from base_plugin import BasePlugin
from android_utils import copy_to_clipboard, run_on_ui_thread
from client_utils import run_on_queue
from ui.bulletin import BulletinHelper
from ui.settings import Divider, Header, Text

__id__ = "lyrics_probe"
__name__ = "Диагностика текстов плеера"
__description__ = "Локальный отчёт о классах плеера для разработки поддержки текстов."
__author__ = "Codex"
__version__ = "0.1.0"
__icon__ = "exteraPlugins/1"
__app_version__ = ">=13.1.1"
__sdk_version__ = ">=1.4.4.3"
__category__ = "tools"

_DEX_NAME = re.compile(r"classes(?:[0-9]+)?\.dex\Z")
_MAX_DEX_BYTES = 64 * 1024 * 1024
_REPORT_LIMIT = 45000


def _dex_class_names(data):
    """Read class descriptors from a standard APK DEX without loading classes."""
    if len(data) < 112 or data[:4] != b"dex\n" or data[7] != 0:
        raise ValueError("Unsupported DEX header")
    # DEX 041 uses a container header/layout; don't interpret it as DEX 035-040.
    if data[4:7] not in (b"035", b"036", b"037", b"038", b"039", b"040"):
        raise ValueError("Unsupported DEX version")
    file_size, header_size, endian = struct.unpack_from("<III", data, 32)
    if header_size != 112 or endian != 0x12345678 or file_size != len(data):
        raise ValueError("Invalid DEX size or byte order")

    def table(header_offset, item_size):
        count, offset = struct.unpack_from("<II", data, header_offset)
        if offset > len(data) or count > (len(data) - offset) // item_size:
            raise ValueError("DEX table is outside the file")
        return count, offset

    string_count, strings_at = table(56, 4)
    type_count, types_at = table(64, 4)
    class_count, classes_at = table(96, 32)

    def u32(offset):
        if offset < 0 or offset + 4 > len(data):
            raise ValueError("Invalid DEX offset")
        return struct.unpack_from("<I", data, offset)[0]

    for index in range(class_count):
        type_index = u32(classes_at + index * 32)
        if type_index >= type_count:
            raise ValueError("Invalid DEX class type")
        string_index = u32(types_at + type_index * 4)
        if string_index >= string_count:
            raise ValueError("Invalid DEX type descriptor")
        cursor = u32(strings_at + string_index * 4)
        # Skip the UTF-16 string length (ULEB128), then read the descriptor.
        for _ in range(5):
            if cursor >= len(data):
                raise ValueError("Truncated DEX string length")
            byte = data[cursor]
            cursor += 1
            if byte < 128:
                break
        else:
            raise ValueError("Invalid DEX string length")
        end = data.find(b"\0", cursor, min(len(data), cursor + 4096))
        if end < 0:
            raise ValueError("Unterminated DEX class descriptor")
        descriptor = data[cursor:end].decode("utf-8", "replace")
        if descriptor.startswith("L") and descriptor.endswith(";"):
            yield descriptor[1:-1].replace("/", ".")


def _is_candidate(name):
    lower = name.lower()
    if "lyric" in lower:
        return True
    own_package = lower.startswith(("com.exteragram.", "org.telegram.", "extera."))
    return own_package and any(
        token in lower for token in ("audioplayer", "musicplayer", ".player.")
    )


def _priority(name):
    lower = name.lower()
    if "lyric" in lower and lower.startswith(("com.exteragram.", "org.telegram.")):
        return (0, name)
    if "lyric" in lower:
        return (1, name)
    return (2, name)


def _signature_report(clazz):
    """Read declarations only: no constructors, hooks or player methods run."""
    from java import jclass

    modifier = jclass("java.lang.reflect.Modifier")
    rows = ["\nCLASS " + str(clazz.getName())]
    parent = clazz.getSuperclass()
    if parent is not None:
        rows.append("extends " + str(parent.getName()))
    interfaces = [str(item.getName()) for item in clazz.getInterfaces()]
    if interfaces:
        rows.append("implements " + ", ".join(interfaces))

    try:
        fields = sorted(clazz.getDeclaredFields(), key=lambda item: str(item.getName()))
        rows.append("FIELDS:")
        for field in fields:
            rows.append("  {} {} {}".format(
                modifier.toString(field.getModifiers()),
                field.getType().getName(), field.getName(),
            ))
    except Exception as error:
        rows.append("FIELDS ERROR: " + str(error)[:200])

    try:
        rows.append("CONSTRUCTORS:")
        for ctor in clazz.getDeclaredConstructors():
            arguments = ", ".join(str(item.getName()) for item in ctor.getParameterTypes())
            rows.append("  ({})".format(arguments))
    except Exception as error:
        rows.append("CONSTRUCTOR ERROR: " + str(error)[:200])

    try:
        methods = sorted(clazz.getDeclaredMethods(), key=lambda item: str(item.getName()))
        rows.append("METHODS:")
        for method in methods:
            if method.isSynthetic():
                continue
            arguments = ", ".join(str(item.getName()) for item in method.getParameterTypes())
            rows.append("  {} {} {}({})".format(
                modifier.toString(method.getModifiers()),
                method.getReturnType().getName(), method.getName(), arguments,
            ))
    except Exception as error:
        rows.append("METHOD ERROR: " + str(error)[:200])
    return "\n".join(rows)


class LyricsProbePlugin(BasePlugin):
    def on_plugin_load(self):
        self._active = True
        self._running = False
        self._report = None

    def on_plugin_unload(self):
        self._active = False

    def create_settings(self):
        return [
            Header(text="Диагностика встроенного плеера"),
            Text(
                text="1. Собрать отчёт",
                subtext="Обычно занимает несколько секунд.",
                icon="msg_search", on_click=self._start,
            ),
            Text(
                text="2. Скопировать отчёт",
                subtext="После проверки вставьте текст в чат с разработчиком.",
                icon="msg_copy", on_click=self._copy,
            ),
            Divider(text=(
                "Отчёт содержит версию приложения, названия классов и сигнатуры. "
                "Собирается локально. Отправка — вручную."
            )),
        ]

    def _start(self, view=None):
        if getattr(self, "_running", False):
            BulletinHelper.show_info("Проверка ещё выполняется.")
            return
        self._running = True
        self._report = None
        BulletinHelper.show_info("Проверяю классы плеера…")
        try:
            run_on_queue(self._collect)
        except Exception:
            self._running = False
            BulletinHelper.show_error("Не удалось запустить проверку.")
            raise

    def _collect(self):
        try:
            from java import jclass
            from org.telegram.messenger import ApplicationLoader

            context = ApplicationLoader.applicationContext
            package = str(context.getPackageName())
            info = context.getApplicationInfo()
            package_info = context.getPackageManager().getPackageInfo(package, 0)
            rows = [
                "LYRICS PROBE 0.1.0",
                "Package: " + package,
                "App version: " + str(package_info.versionName),
                "App code: " + str(package_info.versionCode),
            ]
            paths = [str(info.sourceDir)]
            if info.splitSourceDirs is not None:
                paths.extend(str(path) for path in info.splitSourceDirs)
            candidates = set()
            dex_count = 0
            for path in dict.fromkeys(paths):
                if not self._active:
                    return
                try:
                    with zipfile.ZipFile(path) as archive:
                        for entry in archive.infolist():
                            if not _DEX_NAME.fullmatch(entry.filename):
                                continue
                            dex_count += 1
                            if entry.file_size > _MAX_DEX_BYTES:
                                rows.append("DEX skipped (too large): " + entry.filename)
                                continue
                            try:
                                data = archive.read(entry)
                                for name in _dex_class_names(data):
                                    if _is_candidate(name):
                                        candidates.add(name)
                            except Exception as error:
                                rows.append("DEX ERROR {}: {}".format(entry.filename, str(error)[:200]))
                            finally:
                                data = None
                except Exception as error:
                    rows.append("APK READ ERROR: " + str(error)[:200])

            names = sorted(candidates, key=_priority)
            rows.extend([
                "DEX files: " + str(dex_count),
                "Matching classes: " + str(len(names)),
                "\nCLASS INDEX:",
            ])
            rows.extend(names[:160])
            if len(names) > 160:
                rows.append("Class index truncated.")

            loader = context.getClassLoader()
            java_class = jclass("java.lang.Class")
            character_count = sum(len(row) + 1 for row in rows)
            for index, name in enumerate(names):
                if not self._active:
                    return
                if index >= 80 or character_count >= _REPORT_LIMIT:
                    rows.append("Declaration report truncated.")
                    break
                try:
                    # Explicitly avoid class initialization while inspecting declarations.
                    clazz = java_class.forName(name, False, loader)
                    section = _signature_report(clazz)
                except Exception as error:
                    section = "\nCLASS {}\nLOAD ERROR: {}".format(name, str(error)[:200])
                remaining = max(0, _REPORT_LIMIT - character_count)
                if len(section) > remaining:
                    rows.append(section[:remaining])
                    rows.append("Declaration report truncated.")
                    break
                rows.append(section)
                character_count += len(section) + 1
            if not names:
                rows.append("No matching class names found; this build may use obfuscation.")
            report = "\n".join(rows)
        except Exception as error:
            report = "LYRICS PROBE ERROR\n" + str(error)[:1200]
        finally:
            self._running = False
        if self._active:
            self._report = report
            run_on_ui_thread(lambda: self._notify_done())

    def _notify_done(self):
        if self._active:
            BulletinHelper.show_info("Отчёт готов. Нажмите «2. Скопировать отчёт».")

    def _copy(self, view=None):
        if getattr(self, "_running", False):
            BulletinHelper.show_info("Дождитесь окончания проверки.")
        elif not getattr(self, "_report", None):
            BulletinHelper.show_info("Сначала нажмите «1. Собрать отчёт».")
        else:
            copy_to_clipboard(self._report)
