from __future__ import annotations

from .base import Command
from .bash import BashCommand, ShCommand
from .cat import CatCommand
from .cd import CdCommand
from .clear import ClearCommand
from .curl import CurlCommand
from .echo import EchoCommand
from .fsops import ChmodCommand, ChownCommand, CpCommand, LnCommand, MvCommand
from .history import HistoryCommand
from .id import IdCommand
from .ls import LsCommand
from .mkdir import MkdirCommand
from .ps import PsCommand
from .pwd import PwdCommand
from .rm import RmCommand
from .sudo import SudoCommand
from .sysinfo import (
    AptCommand,
    AptCommandAlias,
    CrontabCommand,
    DateCommand,
    DfCommand,
    DmesgCommand,
    EnvCommand,
    ExportCommand,
    FreeCommand,
    HostnameCommand,
    IfconfigCommand,
    IpCommand,
    LastCommand,
    MountCommand,
    NetstatCommand,
    SsCommand,
    UptimeCommand,
    WCommand,
    WhereisCommand,
    WhichCommand,
    WhoCommand,
)
from .textproc import FindCommand, GrepCommand, HeadCommand, TailCommand, WcCommand
from .touch import TouchCommand
from .uname import UnameCommand
from .wget import WgetCommand
from .whoami import WhoamiCommand


def default_registry() -> dict[str, Command]:
    cmds: list[Command] = [
        # core navigation / filesystem reads
        PwdCommand(),
        CdCommand(),
        LsCommand(),
        CatCommand(),
        EchoCommand(),
        # identity / kernel
        WhoamiCommand(),
        IdCommand(),
        UnameCommand(),
        HostnameCommand(),
        # filesystem mutators
        MkdirCommand(),
        TouchCommand(),
        RmCommand(),
        CpCommand(),
        MvCommand(),
        ChmodCommand(),
        ChownCommand(),
        LnCommand(),
        # shell utilities
        PsCommand(),
        HistoryCommand(),
        ClearCommand(),
        EnvCommand(),
        ExportCommand(),
        WhichCommand(),
        WhereisCommand(),
        # shell re-entry
        BashCommand(),
        ShCommand(),
        SudoCommand(),
        # downloads (imitated)
        WgetCommand(),
        CurlCommand(),
        # text processing
        HeadCommand(),
        TailCommand(),
        WcCommand(),
        GrepCommand(),
        FindCommand(),
        # system / network reconnaissance
        DateCommand(),
        UptimeCommand(),
        DfCommand(),
        FreeCommand(),
        IfconfigCommand(),
        IpCommand(),
        NetstatCommand(),
        SsCommand(),
        MountCommand(),
        DmesgCommand(),
        LastCommand(),
        WhoCommand(),
        WCommand(),
        CrontabCommand(),
        AptCommand(),
        AptCommandAlias(),
    ]
    return {c.name: c for c in cmds}


__all__ = ["Command", "default_registry"]
