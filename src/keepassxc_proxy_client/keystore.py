"""On-disk persistence for KeePassXC Browser Integration associations.

The keystore is a JSON file with this schema:

    {
        "version": 1,
        "associations": {
            "<assoc id from KeePassXC>": "<base64-encoded idKey>"
        }
    }

The default location is OS-appropriate (via platformdirs):

    Linux/BSD:  $XDG_CONFIG_HOME/keepassxc-proxy-client/keys.json
                (fallback: ~/.config/keepassxc-proxy-client/keys.json)
    macOS:      ~/Library/Application Support/keepassxc-proxy-client/keys.json
    Windows:    %APPDATA%\\keepassxc-proxy-client\\keys.json

On POSIX, the directory is created with mode 0700 and the file with 0600.
On Windows, file permissions rely on the user profile ACL.
"""
import base64
import json
import os
import platform
import tempfile

APP_NAME = "keepassxc-proxy-client"
KEYSTORE_FILENAME = "keys.json"
SCHEMA_VERSION = 1


class KeystoreError(Exception):
    pass


class KeystoreFormatError(KeystoreError):
    pass


class AssociationExists(KeystoreError):
    pass


class AssociationNotFound(KeystoreError):
    pass


def default_path():
    """Return the OS-appropriate path to the user's keystore file."""
    try:
        import platformdirs
    except ImportError as e:
        raise KeystoreError(
            "platformdirs is required to resolve the default keystore path; "
            "install it or pass an explicit file path"
        ) from e
    config_dir = platformdirs.user_config_dir(APP_NAME, appauthor=False, roaming=True)
    return os.path.join(config_dir, KEYSTORE_FILENAME)


def _empty_store():
    return {"version": SCHEMA_VERSION, "associations": {}}


def _migrate_legacy(data):
    """Convert the pre-schema single-association shape into the current schema.

    Older `create` output looked like {"name": ..., "public_key": ...}. Detect
    that shape and lift it into the versioned multi-association form so read
    paths keep working. Returns data unchanged if it isn't the legacy shape.
    """
    if isinstance(data, dict) and "version" not in data \
            and set(data.keys()) == {"name", "public_key"}:
        return {
            "version": SCHEMA_VERSION,
            "associations": {data["name"]: data["public_key"]},
        }
    return data


def _validate(data):
    if not isinstance(data, dict):
        raise KeystoreFormatError("keystore root must be an object")
    if data.get("version") != SCHEMA_VERSION:
        raise KeystoreFormatError(
            "unsupported or missing keystore version (expected %d)" % SCHEMA_VERSION
        )
    assoc = data.get("associations")
    if not isinstance(assoc, dict):
        raise KeystoreFormatError("`associations` must be an object")
    for assoc_id, key in assoc.items():
        if not isinstance(key, str):
            raise KeystoreFormatError("association %r value must be a base64 string" % assoc_id)
    return data


def read(path):
    """Load the keystore file. Returns the parsed dict.

    Raises FileNotFoundError if the file does not exist, and KeystoreFormatError
    if it does not match the expected schema.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return _validate(_migrate_legacy(data))


def read_or_empty(path):
    """Like read(), but returns an empty store if the file is missing."""
    try:
        return read(path)
    except FileNotFoundError:
        return _empty_store()


def _atomic_write(path, data):
    """Write data to path atomically (write to tmp + rename), with 0600 mode on POSIX."""
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    if platform.system() != "Windows":
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass

    fd, tmp = tempfile.mkstemp(prefix=".keys-", suffix=".json", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
        if platform.system() != "Windows":
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def list_associations(path):
    """Return a sorted list of association ids stored at `path`."""
    data = read_or_empty(path)
    return sorted(data["associations"].keys())


def load(path, assoc_id):
    """Load a single association from `path` by id.

    Returns the raw idKey bytes. Raises AssociationNotFound if missing.
    """
    data = read_or_empty(path)
    key_b64 = data["associations"].get(assoc_id)
    if key_b64 is None:
        raise AssociationNotFound(
            "association %r not found in %s" % (assoc_id, path)
        )
    return base64.b64decode(key_b64.encode("ascii"))


def save(path, assoc_id, key_bytes, force=False):
    """Persist an association to `path`.

    If `assoc_id` already exists and `force` is False, raises AssociationExists.
    The file is created (with mode 0600 on POSIX) if it does not exist.
    """
    data = read_or_empty(path)
    if assoc_id in data["associations"] and not force:
        raise AssociationExists(
            "association %r already exists in %s; use force=True to overwrite" % (assoc_id, path)
        )
    data["associations"][assoc_id] = base64.b64encode(key_bytes).decode("ascii")
    _atomic_write(path, data)


def delete(path, assoc_id):
    """Remove an association from the keystore. Raises AssociationNotFound if missing."""
    data = read_or_empty(path)
    if assoc_id not in data["associations"]:
        raise AssociationNotFound(
            "association %r not found in %s" % (assoc_id, path)
        )
    del data["associations"][assoc_id]
    _atomic_write(path, data)
