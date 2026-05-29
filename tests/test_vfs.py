import pytest

from honeypot.fs import BaseFS, VFS, resolve


@pytest.fixture
def base():
    raw = {
        "entries": {
            "/": {"type": "dir"},
            "/etc": {"type": "dir"},
            "/etc/passwd": {"type": "file", "content": "root:x:0:0::/root:/bin/bash\n"},
            "/etc/issue": {"type": "file", "content": "Ubuntu\n"},
            "/root": {"type": "dir"},
            "/home": {"type": "dir"},
            "/tmp": {"type": "dir"},
            "/var/log": {"type": "dir"},  # /var auto-created
        }
    }
    return BaseFS(raw)


# ---- resolve() ----------------------------------------------------------

@pytest.mark.parametrize(
    "cwd,path,expected",
    [
        ("/root", "", "/root"),
        ("/root", ".", "/root"),
        ("/root", "..", "/"),
        ("/", "..", "/"),
        ("/root", "a", "/root/a"),
        ("/root", "./a/./b", "/root/a/b"),
        ("/root", "../etc", "/etc"),
        ("/root", "/etc/passwd", "/etc/passwd"),
        ("/root", "~", "/root"),
        ("/root", "~/x", "/root/x"),
        ("/var/log", "../../etc/issue", "/etc/issue"),
        ("/var/log", "../../../..", "/"),
    ],
)
def test_resolve(cwd, path, expected):
    assert resolve(cwd, path) == expected


# ---- BaseFS -------------------------------------------------------------

def test_base_auto_creates_parents(base):
    # /var was never declared explicitly but must exist (parent of /var/log)
    assert base.exists("/var")
    assert base.get("/var").is_dir


def test_base_list_root(base):
    assert base.list("/") == ["etc", "home", "root", "tmp", "var"]


def test_base_list_etc(base):
    assert base.list("/etc") == ["issue", "passwd"]


def test_base_list_missing(base):
    assert base.list("/nope") is None


def test_base_list_on_file_returns_none(base):
    assert base.list("/etc/passwd") is None


# ---- VFS (overlay-backed) -----------------------------------------------

def test_vfs_chdir_and_cwd(base):
    vfs = VFS(base, cwd="/root")
    assert vfs.cwd == "/root"
    vfs.chdir("/etc")
    assert vfs.cwd == "/etc"
    vfs.chdir("..")
    assert vfs.cwd == "/"


def test_vfs_chdir_into_file_raises(base):
    vfs = VFS(base, cwd="/etc")
    with pytest.raises(NotADirectoryError):
        vfs.chdir("/etc/passwd")


def test_vfs_chdir_missing_raises(base):
    vfs = VFS(base)
    with pytest.raises(FileNotFoundError):
        vfs.chdir("/nope")


def test_vfs_read_from_base(base):
    vfs = VFS(base)
    assert vfs.read_text("/etc/passwd").startswith("root:x:0:0")


def test_vfs_write_then_read_in_overlay(base):
    vfs = VFS(base, cwd="/tmp")
    vfs.write_text("hello.txt", "hi")
    assert vfs.read_text("/tmp/hello.txt") == "hi"
    assert "hello.txt" in vfs.list("/tmp")


def test_vfs_write_does_not_mutate_base(base):
    vfs1 = VFS(base, cwd="/tmp")
    vfs1.write_text("a", "1")
    vfs2 = VFS(base, cwd="/tmp")
    # Fresh session does not see vfs1's writes
    assert "a" not in vfs2.list("/tmp")


def test_vfs_mkdir_and_nested_write(base):
    vfs = VFS(base, cwd="/tmp")
    vfs.mkdir("x")
    vfs.chdir("x")
    vfs.write_text("y", "data")
    assert vfs.read_text("/tmp/x/y") == "data"
    assert vfs.list("/tmp/x") == ["y"]


def test_vfs_mkdir_existing_raises(base):
    vfs = VFS(base)
    with pytest.raises(FileExistsError):
        vfs.mkdir("/tmp")


def test_vfs_mkdir_missing_parent_raises(base):
    vfs = VFS(base)
    with pytest.raises(FileNotFoundError):
        vfs.mkdir("/nope/inner")


def test_vfs_unlink_base_file_via_tombstone(base):
    vfs = VFS(base)
    vfs.unlink("/etc/issue")
    assert not vfs.exists("/etc/issue")
    assert vfs.list("/etc") == ["passwd"]


def test_vfs_unlink_directory_raises(base):
    vfs = VFS(base)
    with pytest.raises(IsADirectoryError):
        vfs.unlink("/etc")


def test_vfs_rmdir_nonempty_raises(base):
    vfs = VFS(base)
    with pytest.raises(OSError):
        vfs.rmdir("/etc")


def test_vfs_rmdir_empty_overlay_dir(base):
    vfs = VFS(base, cwd="/tmp")
    vfs.mkdir("emptydir")
    vfs.rmdir("emptydir")
    assert "emptydir" not in vfs.list("/tmp")


def test_vfs_touch_creates_empty_file(base):
    vfs = VFS(base, cwd="/tmp")
    vfs.touch("z")
    assert vfs.read("/tmp/z") == b""


def test_vfs_overlay_overrides_base_file(base):
    vfs = VFS(base)
    vfs.write_text("/etc/issue", "spoofed\n")
    assert vfs.read_text("/etc/issue") == "spoofed\n"
    # base remains intact
    assert base.get("/etc/issue").content == b"Ubuntu\n"


def test_vfs_list_merges_base_and_overlay(base):
    vfs = VFS(base, cwd="/etc")
    vfs.write_text("hosts", "127.0.0.1 localhost\n")
    listing = vfs.list("/etc")
    assert listing == ["hosts", "issue", "passwd"]
