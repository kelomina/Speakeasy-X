# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from typing import Any


class GuiObject:
    """
    Base class for all GUI objects
    """

    curr_handle = 0x120

    def __init__(self):
        self.handle = self.get_handle()

    def get_handle(self):
        tmp = GuiObject.curr_handle
        GuiObject.curr_handle += 4
        return tmp


class Session(GuiObject):
    """
    Represents a windows Session
    """

    def __init__(self, sess_id):
        super().__init__()
        self.id: int = sess_id
        self.stations: dict[int, Station] = {}

    def new_station(self, name="WinSta0"):
        stat = Station(name=name)
        self.stations.update({stat.get_handle(): stat})
        return stat


class Station(GuiObject):
    """
    Represents a window station
    """

    def __init__(self, name=""):
        super().__init__()
        self.name: str = name
        self.desktops: dict[int, Desktop] = {}

    def new_desktop(self, name=""):
        desk = Desktop(name=name)
        self.desktops.update({desk.get_handle(): desk})
        return desk


class Desktop(GuiObject):
    """
    Represents a Desktop object
    """

    def __init__(self, name=""):
        super().__init__()
        self.windows: dict[int, Window] = {}
        self.desktop_window: Window = self.new_window()
        self.name: str = name

    def new_window(self):
        # create the desktop window
        window = Window()
        self.windows.update({window.get_handle(): window})
        return window


class Window(GuiObject):
    """
    Represents a GUI window
    """

    def __init__(self, name=None, class_name=None):
        super().__init__()
        self.name: str | None = name
        self.class_name: str | None = class_name


class WindowClass(GuiObject):
    """
    Represents a GUI window class
    """

    def __init__(self, wclass, name):
        super().__init__()
        self.wclass: Any = wclass
        self.name: str = name


class SessionManager:
    """
    The session manager for the emulator. This will manage things like desktops,
    windows, and session isolation
    """

    def __init__(self, config):
        super().__init__()
        self.sessions: dict[int, Session] = {}
        self.window_classes: dict[int | str, WindowClass] = {}
        self.windows: dict[int | str, Window] = {}
        # Flat handle -> GuiObject index for O(1) lookup in get_gui_object.
        # Holds sessions, stations and desktops (the same set the previous
        # three-level nested scan was able to resolve). Populated below from
        # the per-level dicts so the index keys stay consistent with the
        # existing {session/station/desktop} handle allocations.
        self._handle_index: dict[int, GuiObject] = {}
        self.curr_session: Session | None = None
        self.curr_station: Station | None = None
        self.curr_desktop: Desktop | None = None
        self.config: Any = config
        self.dev_ctx: int = GuiObject.curr_handle

        # create a session 0 and register it in self.sessions. Previously this
        # was never done, so self.sessions was always empty and get_gui_object
        # could not resolve any handle (V2-7-7 P0 bug).
        self.curr_session = Session(sess_id=0)
        self.sessions[self.curr_session.get_handle()] = self.curr_session

        # create WinSta0
        self.curr_station = self.curr_session.new_station(name="WinSta0")

        # Create a desktop
        self.curr_station.new_desktop("Winlogon")
        default = self.curr_station.new_desktop("Default")
        self.curr_station.new_desktop("Disconnect")

        # For now lets default to the Default desktop
        self.curr_desktop = default

        # Build the flat handle index from the per-level dicts so get_gui_object
        # can resolve any session/station/desktop in O(1). The keys are the
        # same handle values already used by the per-level dicts.
        for sess_h, sess in self.sessions.items():
            self._handle_index[sess_h] = sess
            for stat_h, stat in sess.stations.items():
                self._handle_index[stat_h] = stat
                for desk_h, desk in stat.desktops.items():
                    self._handle_index[desk_h] = desk

    def create_window_class(self, class_obj, class_name=None):
        wc = WindowClass(class_obj, class_name)
        atom = wc.get_handle()
        self.window_classes.update({atom: wc})
        if class_name:
            self.window_classes.update({class_name: wc})
        return atom

    def create_window(self, window_name=None, class_name=None):
        wc = Window(window_name, class_name)
        hnd = wc.get_handle()
        self.windows.update({hnd: wc})
        if window_name:
            self.windows.update({window_name: wc})
        return hnd

    def get_window_class(self, atom):
        return self.window_classes.get(atom)

    def get_window(self, handle):
        return self.windows.get(handle)

    def get_device_context(self):
        return self.dev_ctx

    def get_current_desktop(self):
        return self.curr_desktop

    def get_current_station(self):
        return self.curr_station

    def get_gui_object(self, handle):
        # O(1) lookup via the flat handle index built in __init__.
        obj = self._handle_index.get(handle)
        if obj is not None:
            return obj
        # Fallback to the nested scan over the per-level dicts for any
        # session/station/desktop created dynamically after __init__.
        # Iterates dict keys directly (GuiObject.get_handle() mutates the
        # counter, so it must not be called here).
        for sess_h, sess in self.sessions.items():
            if sess_h == handle:
                return sess
            for stat_h, stat in sess.stations.items():
                if stat_h == handle:
                    return stat
                for desk_h, desk in stat.desktops.items():
                    if desk_h == handle:
                        return desk
        return None
