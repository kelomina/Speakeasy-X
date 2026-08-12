# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from collections import OrderedDict, namedtuple
from collections.abc import MutableMapping
from ctypes import *  # noqa
from typing import Any


class EmuStructException(Exception):
    """
    Container class for struct exceptions
    """

    pass


class Enum:
    """
    For now, a basic python object will serve as a C style enum.
    Supports arbitrary attribute access for dynamic enum-style constants.
    """

    def __setattr__(self, name: str, value: Any) -> None:
        object.__setattr__(self, name, value)

    def __getattr__(self, name: str) -> Any:
        raise AttributeError(name)


class PtrMeta(type):
    """
    Metaclass for pointer types
    """

    def __mul__(self, mult):
        return tuple((self, mult))


class Ptr(metaclass=PtrMeta):
    """
    Generic object to identify pointer variables that will be expanded
    according to the "ptr_size" parameter passed to our init
    """

    _points_to_ = None


class CMeta(type):
    """
    meta class to hook __call__ and make __dict__ ordered on all versions
    of python
    """

    @classmethod
    def __prepare__(metacls, name: str, bases: tuple[type, ...], /, **kwds: Any) -> MutableMapping[str, object]:
        return OrderedDict()

    def __new__(self, name, bases, classdict):
        classdict["__ordered__"] = [k for k in classdict.keys() if k not in ("__module__", "__qualname__")]
        return type.__new__(self, name, bases, classdict)

    def __call__(cls, *args, **kwargs):

        obj = type.__call__(cls, *args, **kwargs)
        obj.create_struct()
        return obj

    def __mul__(self, mult):
        return tuple((self, mult))


# 模块级结构体字段缓存
# 键: "{module}.{name}_{ptr_size}" - 含模块限定名，避免 ctypes 按 id() 校验类型时跨模块同名类冲突
# 值: _StructCache(fields, field_name_map, filter_specs)
_StructCache = namedtuple('_StructCache', ['fields', 'field_name_map', 'filter_specs'])
_STRUCT_CACHE: dict[str, _StructCache] = {}


class EmuStruct(metaclass=CMeta):
    """
    Advanced Python class for interacting with C structures
    """

    # Save the unique types we create here
    # This is necessary since the ctypes metaclass won't allow us
    # to assign structures even if the types are identical on the surface.
    # ctypes will test the id (address) of the type to make sure they match
    # upon assignment. Otherwise we will hit spurious TypeErrors.
    __types__: dict[str, type] = {}

    # 类级字段名映射 name -> (type, filtered)，由 create_struct 首次构建后设置；
    # __getattribute__/__setattr__ 据此做 O(1) 查找替代 O(n) 遍历
    _field_name_map: dict = None

    class FilteredStruct(ct.Structure):
        def __hash__(self):
            return hash(repr(self))

    def __init__(self, ptr_size=0, pack=0):

        # Set __dict__ directly here to avoid __getattribute__ loops
        self.__dict__["__pack__"] = pack
        self.__dict__["__struct__"] = None
        self.__dict__["__fields__"] = []
        self.__dict__["__ptrsize__"] = ptr_size
        self.__dict__["__filtermap__"] = {}

    def _is_ctype(self, obj):
        """
        Test whether the object has a ctype base
        """
        tests = (ct._SimpleCData, ct.Structure, ct.Union, ct.Array)
        return any([issubclass(obj, t) for t in tests])

    def create_struct(self, types={}):
        """
        Walk each attribute and handle accordingly. Since ctypes.Structure
        is a metaclass, we have to build the "_fields_" dynamically via a
        factory.

        首次构建后缓存到模块级 _STRUCT_CACHE（键含模块限定名，避免 ctypes 跨模块同名类冲突），
        后续同 (类, ptr_size) 实例直接复用字段列表与字段名映射，仅按实例重建 filtermap。
        """

        if self.__struct__:
            return

        cls = self.__class__
        # 缓存键含模块限定名，避免 ctypes 按 id() 校验类型时跨模块同名类冲突
        cache_key = f"{cls.__module__}.{cls.__name__}_{self.__ptrsize__}"
        cached = _STRUCT_CACHE.get(cache_key)

        if cached is None:
            # 首次构建：遍历 __dict__ 生成字段列表、字段名映射和过滤规格
            fields = []
            field_name_map = {}   # name -> (type, filtered) 供 __getattribute__/__setattr__ O(1) 查找
            filter_specs = []     # (name, kind, _type, count) 用于按实例重建 filtermap
            for d, obj in self.__dict__.items():
                try:
                    if isinstance(obj, tuple):
                        if issubclass(obj[0], EmuStruct):
                            _type, count = obj

                            try:
                                tmp = _type(self.__ptrsize__, self.__pack__)
                                array = [_type(self.__ptrsize__, self.__pack__) for i in range(count)]
                            except TypeError:
                                try:
                                    tmp = _type(self.__ptrsize__)
                                    array = [_type(self.__ptrsize__) for i in range(count)]
                                except TypeError as e:
                                    raise EmuStructException(str(e))

                            ctarray = tmp.__struct__.__class__ * count

                            self.__filtermap__.update({d: array})
                            fields.append((d, ctarray))
                            field_name_map[d] = (ctarray, True)
                            filter_specs.append((d, 'array', _type, count))
                        elif issubclass(obj[0], Ptr):
                            _type, count = obj
                            ptype = self.get_ptr_field()
                            arr_type = ptype * count
                            fields.append((d, arr_type))
                            field_name_map[d] = (arr_type, False)

                except TypeError:
                    continue
                try:
                    if self._is_ctype(obj):
                        # Simply append ctypes since they will be handled
                        # automatically
                        fields.append((d, obj))
                        field_name_map[d] = (obj, False)
                    elif issubclass(obj, Ptr):
                        # Expand pointers to the required width
                        ptype = self.get_ptr_field()
                        fields.append((d, ptype))
                        field_name_map[d] = (ptype, False)

                    elif issubclass(obj, EmuStruct):
                        # Allow nesting of this class which we are calling a
                        # "filter class". That is, when fields are accessed in the
                        # underlying ctypes struct, we pass the getattr/setattr through
                        if obj.__name__ != self.__class__.__name__:
                            try:
                                filt = obj(self.__ptrsize__, self.__pack__)
                            except TypeError:
                                try:
                                    filt = obj(self.__ptrsize__)
                                except TypeError as e:
                                    raise EmuStructException(str(e))
                            cts = filt.__struct__
                            self.__filtermap__.update({d: filt})
                            fields.append((d, cts.__class__))
                            field_name_map[d] = (cts.__class__, True)
                            filter_specs.append((d, 'single', obj, None))

                except TypeError:
                    continue
            cached = _StructCache(fields=fields, field_name_map=field_name_map, filter_specs=filter_specs)
            _STRUCT_CACHE[cache_key] = cached
            self.__dict__["__fields__"] = fields
        else:
            # 复用缓存：直接使用缓存的字段列表，按实例重建 filtermap（filtermap 含状态不可共享）
            self.__dict__["__fields__"] = cached.fields
            for name, kind, _type, count in cached.filter_specs:
                if kind == 'array':
                    try:
                        array = [_type(self.__ptrsize__, self.__pack__) for i in range(count)]
                    except TypeError:
                        try:
                            array = [_type(self.__ptrsize__) for i in range(count)]
                        except TypeError as e:
                            raise EmuStructException(str(e))
                    self.__filtermap__.update({name: array})
                else:  # 'single'
                    try:
                        filt = _type(self.__ptrsize__, self.__pack__)
                    except TypeError:
                        try:
                            filt = _type(self.__ptrsize__)
                        except TypeError as e:
                            raise EmuStructException(str(e))
                    self.__filtermap__.update({name: filt})

        # 类级属性 _field_name_map 供 __getattribute__/__setattr__ O(1) 查找
        cls._field_name_map = cached.field_name_map
        self.__init_struct()

    def get_ptr_field(self):
        """
        Get ctypes value for the required pointer size
        """
        if self.__ptrsize__ == 4:
            return ct.c_uint32
        elif self.__ptrsize__ == 8:
            return ct.c_uint64
        else:
            return ct.c_void_p

    def get_pack(self):
        """
        Get the required structure pack (defaults to pointer size)
        """
        if self.__pack__:
            return self.__pack__
        else:
            if self.__ptrsize__:
                return self.__ptrsize__ * 2
            else:
                return 1

    def _link_cstructs(self, obj):
        """
        Link the ctypes structures together in the case of nesting.
        This will allow the buffer API to convert it to bytes easily
        """
        for fname, subobj in obj.__filtermap__.items():
            if isinstance(subobj, list):
                x = getattr(obj.__struct__, fname)

                for i, e in enumerate(x):
                    self._link_cstructs(subobj[i])
                    x[i] = subobj[i].__struct__

            elif isinstance(subobj, EmuStruct):
                self._link_cstructs(subobj)
                setattr(obj.__struct__, fname, subobj.__struct__)

    def get_bytes(self):
        """
        Convert the structure to bytes and respecting endianness
        """

        self._link_cstructs(self)

        struct = self.__struct__
        # V1-S-14: 用 string_at 一步序列化，替代 逐字节 c_ubyte 数组 + memmove + 切片
        return ct.string_at(ct.byref(struct), ct.sizeof(struct))

    def sizeof(self):
        """
        Get the size of the C structure
        """
        return ct.sizeof(self.__struct__)

    def _deep_cast(self, obj, bytez, offset):

        # V1-S-15: 用 from_buffer_copy 避免中间 bytearray 切片；
        # 与原 from_buffer(bytearray(slice)) 语义一致（均拷贝数据到结构体自有缓冲）
        obj.__struct__ = type(obj.__struct__).from_buffer_copy(bytez, offset[0])
        for fn, c in obj.__fields__:
            subobj = obj.__filtermap__.get(fn)
            if subobj:
                if isinstance(subobj, list):
                    for sso in subobj:
                        self._deep_cast(sso, bytez, offset)
                else:
                    self._deep_cast(subobj, bytez, offset)
            else:
                offset[0] += ct.sizeof(c)

    def cast(self, bytez):
        """
        Convert a bytes object to the C structure by "casting" them
        """
        offset = [0]
        self._deep_cast(self, bytez, offset=offset)
        return self

    def get_cstruct(self):
        return self.__struct__.__class__

    def get_sub_field_name(self, cstruc, offset):
        for name, t in cstruc._fields_:
            noff = cstruc.__dict__[name].offset
            nsize = cstruc.__dict__[name].size
            if offset == noff:
                return name
            elif noff < offset < noff + nsize:
                # access into the sub-structure recursively
                return name + "." + self.get_sub_field_name(t, offset - noff)

    def get_field_name(self, offset):
        cstruc = self.get_cstruct()
        for name, t in self.__fields__:
            noff = cstruc.__dict__[name].offset
            nsize = cstruc.__dict__[name].size
            if offset == noff:
                return name
            elif noff < offset < noff + nsize:
                # access into the sub-structure
                return name + "." + self.get_sub_field_name(t, offset - noff)
        return None

    def __struct_factory(self, name):
        """
        Factory used to generate ctypes structures using the ctypes metaclass
        """
        _type_name = f"ct{name}{self.__ptrsize__}"
        # 缓存键含模块限定名，避免跨模块同名类共用同一 ctypes 类型（ctypes 按 id() 校验）
        _cache_key = f"{self.__class__.__module__}.{self.__class__.__name__}_{self.__ptrsize__}"
        _type = EmuStruct.__types__.get(_cache_key)
        if not _type:
            _type = type(
                _type_name,
                (self.__class__.FilteredStruct,),
                {"_pack_": self.get_pack(), "_layout_": "ms", "_fields_": self.__fields__},
            )
            EmuStruct.__types__[_cache_key] = _type
        return _type

    def __init_struct(self):
        self.__struct__ = self.__struct_factory(self.__class__.__name__)()
        return self.__struct__

    def __setattr__(self, name, value):
        """
        Hook setattr so that accessing the underlying ctypes structure can be
        handled correctly. 使用类级 _field_name_map O(1) 查找替代 O(n) 遍历。
        """
        struct = self.__struct__
        if struct:
            fnm = type(self)._field_name_map
            if fnm and name in fnm:
                if isinstance(value, bytes):
                    barray = getattr(struct, name)
                    barray[: len(value)] = value
                    return
                struct.__setattr__(name, value)
                return
        super().__setattr__(name, value)

    def __getattribute__(self, name):
        """
        Hook getattribute so that accessing the underlying ctypes structure
        can be handled correctly. 使用类级 _field_name_map O(1) 查找替代 O(n) 遍历。
        """
        try:
            struct = super().__getattribute__("__struct__")
            if struct:
                fnm = type(self)._field_name_map
                entry = fnm.get(name) if fnm else None
                if entry is not None:
                    _ftype, filtered = entry
                    if filtered:
                        fm = super().__getattribute__("__filtermap__")
                        filt_obj = fm.get(name)
                        if filt_obj:
                            return filt_obj
                    return struct.__getattribute__(name)
        except AttributeError:
            pass
        return super().__getattribute__(name)


class EmuUnion(EmuStruct, metaclass=CMeta):
    class FilteredStruct(ct.Union):
        def __hash__(self):
            return hash(repr(self))
