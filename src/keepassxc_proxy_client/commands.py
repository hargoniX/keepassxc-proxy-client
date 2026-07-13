import base64
import json
import sys

import keepassxc_proxy_client.protocol
from keepassxc_proxy_client import keystore


def _authenticate(connection, path, assoc_id=None):
    """Authenticate against a keystore.

    If `assoc_id` is given, only that association is tried. Otherwise every
    stored association is tried until one authenticates.

    Returns True on success. Prints a diagnostic and returns False if the
    keystore is empty, the requested id is missing, or no candidate
    authenticated.
    """
    if assoc_id is not None:
        try:
            key_bytes = keystore.load(path, assoc_id)
        except keystore.AssociationNotFound as e:
            print(str(e))
            return False
        connection.load_associate(assoc_id, key_bytes)
        if connection.test_associate():
            return True
        print("Association %r did not authenticate against the running KeePassXC instance" % assoc_id)
        return False

    ids = keystore.list_associations(path)
    if not ids:
        print("No associations stored in %s" % path)
        return False

    for candidate in ids:
        key_bytes = keystore.load(path, candidate)
        connection.load_associate(candidate, key_bytes)
        if connection.test_associate():
            return True

    print("None of the stored associations authenticated against the running KeePassXC instance")
    return False


def cmd_create(args):
    connection = keepassxc_proxy_client.protocol.Connection()
    connection.connect()
    connection.associate()

    if not connection.test_associate():
        print("For some reason the newly created association is invalid, this should not be happening")
        sys.exit(1)

    name, public_key = connection.dump_associate()

    if args.save:
        path = args.file
        try:
            keystore.save(path, name, public_key, force=args.force)
        except keystore.AssociationExists as e:
            print(str(e))
            print("Re-run with --force to overwrite.")
            sys.exit(1)
        print("Saved association %r to %s" % (name, path))
        return

    out = {
        "version": keystore.SCHEMA_VERSION,
        "associations": {
            name: base64.b64encode(public_key).decode("ascii"),
        },
    }
    print(json.dumps(out))


def cmd_get(args):
    path = args.file

    connection = keepassxc_proxy_client.protocol.Connection()
    connection.connect()
    if not _authenticate(connection, path, args.id):
        sys.exit(1)

    logins = connection.get_logins(args.url)
    if not logins:
        print("No logins found for the given URL")
        sys.exit(1)

    print(logins[0]["password"])


def cmd_totp(args):
    path = args.file

    connection = keepassxc_proxy_client.protocol.Connection()
    connection.connect()
    if not _authenticate(connection, path, args.id):
        sys.exit(1)

    totp_value = connection.get_totp(args.uuid)
    if not totp_value:
        print("No totp found for the given UUID")
        sys.exit(1)

    print(totp_value)


def cmd_unlock(args):
    path = args.file

    connection = keepassxc_proxy_client.protocol.Connection()
    connection.connect()
    if not _authenticate(connection, path, args.id):
        sys.exit(1)

    print(connection.test_associate(True))
