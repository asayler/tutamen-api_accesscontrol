# -*- coding: utf-8 -*-

# Andy Sayler
# Copyright 2015


### Imports ###

import abc
import uuid

from pcollections import be_redis_atomic as dso
from pcollections import factories as dsf
from pcollections import keys as dsk


### Constants ###

_INDEX_OBJ_TYPE = dso.MutableSet
_INDEX_KEY_TYPE = dsk.StrKey
_METAINDEX_POSTFIX = "_metaindex"
_INDEX_POSTFIX = "_index"


### Exceptions ###

class ObjectDNE(Exception):

    def __init__(self, key):

        # Call Parent
        msg = "Object '{:s}' does not exist".format(key)
        super().__init__(msg)


### Abstarct Objects ###

class PersistentObjectServer(object, metaclass=abc.ABCMeta):

    def __init__(self, driver):

        # Check Args
        # TODO: Verify driver if of appropriate type

        # Call Parent
        super().__init__()

        # Save Attrs
        self._driver = driver


    def make_factory(self, obj_type, key_type=dsk.StrKey, key_kwargs={}):
        return dsf.Instancefactory(self._driver, obj_type,
                                   key_type=key_type, key_kwargs=key_kwargs)

class PersistentObject(object, metaclass=abc.ABCMeta):

    def __init__(self, srv, key):
        """Initialize Object"""

        # Check Args
        if not isinstance(srv, PersistentServer):
            msg = "'srv' must be of type '{}', ".format(PersistentServer)
            msg += "not '{}'".format(type(srv))
            raise TypeError(msg)

        # Call Parent
        super().__init__()

        # Save Attrs
        self._srv = srv
        self._key = key

    @property
    def key(self):
        return self._key

    @abc.abstractmethod
    def destory(self):
        pass

### Objects ###

class Index(PersistentObject):

    def __init__(self, *args, **kwargs):
        """Initialize Object"""

        # Call Parent
        super().__init__(*args, **kwargs)

        # Create Index Factory
        factory = self._srv.make_factory(_INDEX_OBJ_TYPE, key_type=_INDEX_KEY_TYPE)
        index_key = self.key + _INDEX_POSTFIX
        index = factory.from_raw(index_key)
        if not index.exists():
            index.create(set())
        self._index = index

    def add(self, obj):

        # Check Args
        if not isinstance(obj, Indexed):
            msg = "'obj' must be an instance of '{}', ".format(Indexed)
            msg += "not '{}'".format(type(obj))
            raise TypeError(msg)

        # Add Object Key
        self._index.add(obj.key)

    def remove(self, obj):

        # Check Args
        if not isinstance(obj, Indexed):
            msg = "'obj' must be an instance of '{}', ".format(Indexed)
            msg += "not '{}'".format(type(obj))
            raise TypeError(msg)

        # Remove Object Key
        self._index.discard(obj.key)

    def members(self):

        # Return index memebership
        return set(self._index)

    def destroy(self):

        # Unregister objects
        for obj_key in self._index.memebers():
            obj = IndexedObject(self._srv, obj_key)
            obj.index_unregister(index)

        # Cleanup backend object
        self._index.rem()

        # Call Parent
        super().destroy()

class Indexed(PersistentObject):

    def __init__(self, *args, **kwargs):
        """Initialize Object"""

        # Call Parent
        super().__init__(*args, **kwargs)

        # Create Metaindex
        metaindex_key = self._key + _METAINDEX_POSTFIX
        self._metaindex = Index(self._srv, metaindex_key)

    def register(self, index):

        # Check Args
        if not isinstance(index, Index):
            msg = "'index' must be an instance of '{}', ".format(Index)
            msg += "not '{}'".format(type(index))
            raise TypeError(msg)

        # Add Index Key
        self._metaindex.add(index.key)
        index.add(self.key)

    def unregister(self, index):

        # Check Args
        if not isinstance(index, Index):
            msg = "'index' must be an instance of '{}', ".format(Index)
            msg += "not '{}'".format(type(index))
            raise TypeError(msg)

        # Remove Index Key
        index.remove(self.key)
        self._metaindex.remove(index.key)

    def destroy(self):

        # Unregister from indexes
        for idx_key in self._metaindex.members():
            index = Index(self._srv, idx_key)
            self.index_unregister(index)

        # Cleanup metaindex
        self._metaindex.destroy()

        # Call Parent
        super().destroy()