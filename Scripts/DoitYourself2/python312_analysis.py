"""
Python 3.12 Dictionary Internal Structure Research

Based on CPython 3.12.11 source code, here's the dict object layout:

PyDictObject structure (from dictobject.h):
typedef struct {
    PyObject_HEAD
    Py_ssize_t ma_used;          /* Number of used slots */
    uint64_t ma_version_tag;     /* Global version tag */
    PyDictKeysObject *ma_keys;   /* Pointer to keys object */
    PyObject **ma_values;        /* Pointer to values array (or NULL) */
} PyDictObject;

PyDictKeysObject structure:
typedef struct {
    PyObject_VAR_HEAD
    Py_ssize_t dk_refcnt;       /* Reference count */
    Py_ssize_t dk_log2_size;    /* log2(dk_size) */  
    Py_ssize_t dk_log2_index_bytes; /* log2(bytes per index) */
    Py_ssize_t dk_kind;         /* Dict kind (DICT_KEYS_GENERAL, etc) */
    Py_ssize_t dk_version;      /* Version number */
    Py_ssize_t dk_usable;       /* Number of usable entries */
    Py_ssize_t dk_nentries;     /* Number of entries */
    char dk_indices[];          /* Variable size index array */
    /* PyDictKeyEntry dk_entries[]; follows after indices */
} PyDictKeysObject;

PyDictKeyEntry structure:
typedef struct {
    Py_hash_t me_hash;    /* Hash value of the key */
    PyObject *me_key;     /* Key object pointer */
    PyObject *me_value;   /* Value object pointer */
} PyDictKeyEntry;

Memory Layout Analysis for flag_dict:
- The dict address we get points to PyDictObject
- ma_keys points to PyDictKeysObject  
- dk_entries contains the key-value pairs
- Each entry has me_key (integer) and me_value (single char string)

Strategy:
1. Read PyDictObject to get ma_keys pointer
2. Follow ma_keys to PyDictKeysObject
3. Calculate dk_entries location (after dk_indices array)
4. Read each PyDictKeyEntry to get key-value pairs
5. Reconstruct flag by sorting by key (original index)

Key offsets (64-bit):
- PyDictObject.ma_keys is at offset 24 (0x18)
- PyDictKeysObject.dk_nentries is at offset 48 (0x30)
- dk_entries starts after dk_indices array
"""

print("Python 3.12 Dict Structure Analysis")
print("===================================")
print("PyDictObject layout (what we get from id(flag_dict)):")
print("  +0x00: PyObject_HEAD (refcnt, type)")
print("  +0x10: ma_used (number of used slots)")  
print("  +0x18: ma_version_tag")
print("  +0x20: ma_keys -> PyDictKeysObject")
print("  +0x28: ma_values (NULL for combined dicts)")
print()
print("PyDictKeysObject layout:")
print("  +0x00: PyObject_VAR_HEAD")
print("  +0x18: dk_refcnt") 
print("  +0x20: dk_log2_size")
print("  +0x28: dk_log2_index_bytes")
print("  +0x30: dk_kind")
print("  +0x38: dk_version")  
print("  +0x40: dk_usable")
print("  +0x48: dk_nentries (number of entries)")
print("  +0x50: dk_indices[] (variable size)")
print("  +???: dk_entries[] (after indices)")